{-# LANGUAGE OverloadedStrings #-}

{- |
  Module      :  System.Posix.Syslog.TCP
  Maintainer  :  omeragacan@gmail.com
  Stability   :  provisional
  Portability :  Posix

  Log messages to syslog over a network via TCP, with protocols such as
  <https://tools.ietf.org/html/rfc5423 RFC 5424> or
  <https://tools.ietf.org/html/rfc3163 RFC 3164>.

  Most of the code adapted from <http://hackage.haskell.org/package/hsyslog-udp hsyslog-udp>.

-}
module System.Posix.Syslog.TCP
  (
    -- * Haskell API to syslog via TCP
    initSyslog
  , SyslogFn
  , SyslogConn (..)
  , SyslogConfig (..)
  , defaultConfig

    -- * Utilities for constructing `SyslogConfig`
  , getAppName
  , getHostName
  , getProcessId

    -- * Protocols for use with 'SyslogConfig'
  , Protocol
  , rfc5424TCPProtocol
  , rfc3164TCPProtocol
  , rsyslogTCPProtocol

    -- * Syslog TCP packet component datatypes
    -- ** Re-exports from <http://hackage.haskell.org/package/hsyslog-4 hsyslog>
  , L.Priority (..)
  , L.Facility (..)
  , L.PriorityMask (..)

    -- ** Newtypes for various String/Int values
    -- | Refer to
    -- <https://tools.ietf.org/html/rfc5424#section-6.2 RFC 5424 section 6.2>
    -- as to the purpose of each.
  , AppName (..)
  , HostName (..)
  , ProcessID (..)
  , MessageID (..)

    -- ** Type aliases
    -- | What syslog refers to as 'L.Priority',
    -- <https://tools.ietf.org/html/rfc5424 RFC 5424> calls 'Severity'.
  , Severity
  , SeverityMask
  ) where

--------------------------------------------------------------------------------
import Control.Exception (onException, mask)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Monoid
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time
import qualified Network.Socket as N
import qualified Network.Socket.ByteString as N
import qualified System.Posix.Syslog as L
import System.Posix.Syslog.UDP hiding (Protocol, SyslogConfig (..), SyslogFn,
                                defaultConfig, initSyslog, rfc3164Packet,
                                rfc3164Protocol, rfc5424Packet, rfc5424Protocol,
                                rsyslogPacket, rsyslogProtocol)
--------------------------------------------------------------------------------

type SyslogFn
  =  L.Facility -- ^ facility to log to
  -> Severity   -- ^ severity under which to log
  -> T.Text     -- ^ message body (should not contain newline)
  -> IO ()

data SyslogConn = SyslogConn
  { -- | Callback for sending logs to the connected remote syslog server. This
    -- function re-throws exceptions, blocks when the TCP socket is not ready
    -- for writing.
    _syslogConnSend  :: SyslogFn
    -- | Callback for closing the connection.
  , _syslogConnClose :: IO ()
  }

-- | Connect to the remote syslog server over TCP.
--
-- See also documentation for `SyslogConn`.
initSyslog :: SyslogConfig -> IO SyslogConn
initSyslog config = do
    let addr = _address config
    mask $ \restore -> do
      socket <- N.socket (N.addrFamily addr) (N.addrSocketType addr) (N.addrProtocol addr)
      restore (N.connect socket (N.addrAddress addr)) `onException` N.close socket

      let
        send_fn fac sev msg =
          case maskedPriVal (_severityMask config) fac sev of
            Nothing -> return ()
            Just priVal -> do
              time <- getCurrentTime
              let bs = getProtocol (_protocol config)
                       priVal time (_hostName config) (_appName config)
                       (_processId config) msg
              N.sendAll socket bs

        close_fn = N.close socket

      return (SyslogConn send_fn close_fn)

-- | Configuration options for connecting and logging to your syslog socket.
data SyslogConfig = SyslogConfig
  { _appName :: !AppName
    -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.5 APP-NAME>@;
    -- fetch via 'getAppName'
  , _hostName :: !HostName
    -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.4 HOSTNAME>@;
    -- fetch via 'getHostName'
  , _processId :: !ProcessID
    -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.6 PROCID>@;
    -- fetch via 'getProcessId'
  , _severityMask :: !SeverityMask
    -- ^ whitelist of priorities of logs to send
  , _address :: !N.AddrInfo
    -- ^ where to send the syslog packets; find via 'N.getAddrInfo'
  , _protocol :: !Protocol
    -- ^ protocol for formatting the message, such as 'rfc5424TCPProtocol' or
    -- 'rfc3164TCPProtocol'
  }

-- | A helper for constructing a 'SyslogConfig'. Uses `rsyslogTCPProtocol`.
-- Returns `Nothing` when `N.getAddrInfo` fails.
defaultConfig :: N.HostName -> N.ServiceName -> IO (Maybe SyslogConfig)
defaultConfig host port = do
    appName <- getAppName
    hostName <- getHostName
    processId <- getProcessId
    addrs <- N.getAddrInfo (Just N.defaultHints) (Just host) (Just port)
    return $ case addrs of
      [] ->
        Nothing
      address : _ ->
        Just SyslogConfig
          { _appName = appName
          , _hostName = hostName
          , _processId = processId
          , _severityMask = L.NoMask
          , _address = address
          , _protocol = rsyslogTCPProtocol
          }

{-
test :: T.Text -> IO ()
test str = do
    Just cfg <- defaultConfig "127.0.0.1" "8012"
    log <- initSyslog cfg
    log USER Debug str
-}

--------------------------------------------------------------------------------
-- * Protocol implementations adapted from
-- <http://hackage.haskell.org/package/hsyslog-udp hsyslog-udp>.

newtype Protocol = Protocol
  { getProtocol
      :: PriVal
      -> UTCTime
      -> HostName
      -> AppName
      -> ProcessID
      -> T.Text
      -> BS.ByteString }

rfc5424TCPPacket
  :: FormatTime t
  => PriVal
  -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.1 PRI>@;
  -- construct via 'maskedPriVal'
  -> t
  -- ^ time of message, converted to
  -- @<https://tools.ietf.org/html/rfc5424#section-6.2.3 TIMESTAMP>@
  -> HostName
  -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.4 HOSTNAME>@;
  -- fetch via 'getHostName'
  -> AppName
  -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.5 APP-NAME>@;
  -- fetch via 'getAppName'
  -> ProcessID
  -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.6 PROCID>@;
  -- fetch via 'getProcessId'
  -> Maybe MessageID
  -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.2.7 MSGID>@
  -> Maybe StructuredData
  -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.3 STRUCTURED-DATA>@
  -- (unsupported)
  -> T.Text
  -- ^ see @<https://tools.ietf.org/html/rfc5424#section-6.4 MSG>@
  -> BS.ByteString
rfc5424TCPPacket priVal time hostName' appName' processId' messageId _ message =
         formatPriVal priVal
     <>  version
    `sp` mkTime time
    `sp` mkHost hostName'
    `sp` mkApp appName'
    `sp` mkProcId processId'
    `sp` maybe nilValue mkMsgId messageId
    `sp` structData
    `sp` T.encodeUtf8 message
     <>  "\n"
  where
    version = "1"
    mkTime = rfc3339Timestamp
    mkHost (HostName x) = notEmpty x
    mkApp (AppName x) = notEmpty x
    mkProcId (ProcessID x) = notEmpty x
    mkMsgId (MessageID x) = notEmpty x
    structData = nilValue

rfc5424TCPProtocol :: Protocol
rfc5424TCPProtocol =
  Protocol $ \priVal time hostName' appName' processId' message ->
    rfc5424TCPPacket priVal time hostName' appName'
      processId' Nothing Nothing message

-- | Construct a syslog TCP packet as dictated by
-- <https://tools.ietf.org/html/rfc3164 RFC 3164>. Note that fields in a syslog
-- packet are whitespace-delineated, so don't allow whitespace in anything but
-- the log message!

rfc3164TCPPacket
  :: FormatTime t
  => PriVal
  -- ^ see @<https://tools.ietf.org/html/rfc3164#section-4.1.1 PRI>@;
  -- construct via 'maskedPriVal'
  -> t
  -- ^ time of message, converted to @TIMESTAMP@ in
  -- @<https://tools.ietf.org/html/rfc3164#section-4.1.2 HEADER>@
  -> HostName
  -- ^ the @HOSTNAME@ of the
  -- @<https://tools.ietf.org/html/rfc3164#section-4.1.2 HEADER>@;
  -- fetch via 'getHostName'
  -> AppName
  -- ^ the program name in the @TAG@ portion of the
  -- @<https://tools.ietf.org/html/rfc3164#section-4.1.3 MSG>@; fetch via
  -- 'getAppName'
  -> ProcessID
  -- ^ the process identifier in the @TAG@ portion of the
  -- @<https://tools.ietf.org/html/rfc3164#section-4.1.3 MSG>@; fetch via
  -- 'getProcessId'
  -> T.Text
  -- ^ the @CONTENT@ portion of the
  -- @<https://tools.ietf.org/html/rfc3164#section-4.1.3 MSG>@
  -> BS.ByteString
rfc3164TCPPacket = rfc3164Variant timeFormat
  where
    timeFormat = BS8.pack . formatTime defaultTimeLocale "%b %e %X"

rfc3164TCPProtocol :: Protocol
rfc3164TCPProtocol = Protocol rfc3164TCPPacket

-- | Recommended rsyslog template
-- @<http://www.rsyslog.com/doc/v8-stable/configuration/templates.html RSYSLOG_ForwardFormat>@.
-- Same fields as RFC 3164, but with an RFC 3339 high-precision timestamp.
rsyslogTCPPacket
  :: FormatTime t
  => PriVal
  -> t
  -> HostName
  -> AppName
  -> ProcessID
  -> T.Text
  -> BS.ByteString
rsyslogTCPPacket = rfc3164Variant rfc3339Timestamp

rsyslogTCPProtocol :: Protocol
rsyslogTCPProtocol = Protocol rsyslogTCPPacket

formatPriVal :: PriVal -> BS.ByteString
formatPriVal (PriVal x) = "<" <> BS8.pack (show x) <> ">"

nilValue :: BS.ByteString
nilValue = "-"

notEmpty :: BS.ByteString -> BS.ByteString
notEmpty bs = if BS.null bs then nilValue else bs

rfc3164Variant
  :: (t -> BS.ByteString)
  -> PriVal
  -> t
  -> HostName
  -> AppName
  -> ProcessID
  -> T.Text
  -> BS.ByteString
rfc3164Variant timeFormat priVal time hostName' appName' processId' message =
         formatPriVal priVal
     <>  timeFormat time
    `sp` mkHost hostName'
    `sp` mkTag appName' processId'
    `sp` T.encodeUtf8 message
     <>  "\n"
  where
    mkHost (HostName x) = notEmpty x
    mkTag (AppName name) (ProcessID procId) = name <> "[" <> procId <> "]:"

sp :: BS.ByteString -> BS.ByteString -> BS.ByteString
sp b1 b2 = b1 <> " " <> b2
{-# INLINE sp #-}
