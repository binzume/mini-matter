# [WIP] Simple Matter implementation for ESP32

MatterデバイスのふりをしてWiFiのSSIDとパスワードを取得するための実装。

[esp-matter](https://github.com/espressif/esp-matter) は巨大で、WiFiのセットアップだけに利用するには、メモリとFlashを圧迫するので作りました。

AndroidのGoogle Homeアプリで接続して、WiFiのSSIDとパスワードを設定するところまで動きます。iOSはHomeハブが無いと設定できないので、まだ試してません。

起動時にシリアルポートにコミッショニング用のQRコードのURLが出力されます。matter_config.hの設定を変えない限り固定です。

# License

MIT License
