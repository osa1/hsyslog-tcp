# 0.2.1.0

- Socket leak in `initSyslog` on sync (e.g. `connect()` failure) and async
  exceptions fixed.
