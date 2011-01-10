"%WIX%\bin\heat" dir fio            -gg -sfrag -scom -out cygwin.wxs   -scom -sreg -dr cygwin   -ke -cg cygwin
"%WIX%\bin\heat" dir ..\..\examples -gg -sfrag -scom -out examples.wxs -scom -sreg -dr examples -ke -cg examples
