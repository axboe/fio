"%WIX%\bin\candle" cygwin.wxs
"%WIX%\bin\candle" install.wxs
"%WIX%\bin\candle" examples.wxs
"%WIX%\bin\light" install.wixobj cygwin.wixobj examples.wixobj -ext WixUIExtension -out fio.msi