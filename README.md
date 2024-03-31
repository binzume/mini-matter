# [WIP] Simple Matter implementation for ESP32

MatterデバイスのふりをしてWiFiのSSIDとパスワードを取得するためのライブラリです。

[esp-matter](https://github.com/espressif/esp-matter) は巨大で、WiFiのセットアップだけに利用するには、メモリとFlashを圧迫するので作りました。

AndroidのGoogle Homeアプリで接続して、WiFiのSSIDとパスワードを設定するところまで動きます。iOSはHomeハブが無いと設定できないので、まだ試してません。

## Usage

T.B.D.

platform.ioでビルドできます。ライブラリとしてのインターフェイスは今後整理するかもしれません。

### platformio.ini

```ini
lib_deps =
       https://github.com/binzume/mini-matter.git#main
```

### Example

[example.cpp](src/example.cpp)

WiFiの設定済みであればそのまま起動し、未設定であればMatterのコミッショニングが開始されます。

コミッショニング前に、シリアルポートにコミッショニング用のQRコードのURLを出力します。
matter_config.hの設定を変えない限り固定です。

特に設定を変えていなければ以下のQRコードが使えます。

![QR](https://chart.apis.google.com/chart?chs=200x200&cht=qr&chl=MT:Y.K90KE600KA0648G00)

# License

MIT License
