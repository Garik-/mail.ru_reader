Mail.ru History Reader
===
### Инструкция пользователя
История Mail.ru Агента представляется собой файл mra.dbs, который является дампом памяти и обычно расположен по пути %Application Data%\Mra\Base\mra.dbs.

	Windows XP  C:\Documents and Settings\%username%\Application Data\
	Windows 7	С:\Users\%username%\AppData\Roaming\

Раздобыть чужую переписку можно разными способами, это тема отдельного разговора, а самый простой вариант, на мой взгляд, придти и скопировать (важно, чтобы Mail.Ru Агент не был запущен, а то он не даст скопировать файл т.к. сам работает с ним).

Открыв Mail.ru History Reader в главном меню выбираем "История - > Открыть" и указываем программе путь к нужному файлу истории. 
Если в истории храниться переписка не одного пользователя, это отобразится в выпадающем списке, который расположен под меню.
Таблица "Почта" показывает список e-mail с которыми переписывался данный пользователь.
Переписка открывается двойным кликом по нужной строке таблицы.
### Примеры кода
Получения пути для файла mra.dbs:

	#include "tchar.h"
	TCHAR path[MAX_PATH]; // сюда упадет путь для текущего пользователя  
	ExpandEnvironmentStrings(_TEXT("%appdata%\\Mra\\Base\\mra.dbs"),path,sizeof(path));
	
Закрыть открытый агент. Данной фишкой со мной поделился int3;, который среверсил это из файла установщика Mail.ru Агента:

	#define   WM_MRA_SHUTDOWN 0x3B9ACA01
	SendNotifyMessageW((FindWindowA("MraWClass",NULL)),(RegisterWindowMessageA("Mra shutdown")),WM_MRA_SHUTDOWN,NULL);

### Ссылки
  - [Блог Gar|k-а](http://c0dedgarik.blogspot.ru/)
  - [Страница программы на ачате](https://forum.antichat.ru/thread114077.html)
  - [PDF статьи из 159 выпуска Xakep](https://dl.dropbox.com/u/64727368/mra.reader_xa159.pdf)
