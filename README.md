# CPP_TestTask

Описание:
Создание сервер-клиент, где клиент обращается к серверу за сканированием определенной 
директории на поиск вредоносных файлов и выводит ответ от сервера на консоль.
А сервер  после подключения к нему клиента, с помощью класса Scanner запускает сканирование и затем отправляет ответ.
Scanner открывает дирректорию, читает из нее файлы в цикле. Файл отправляется на проверку подозрительных строк, там открываются потоки на каждую вредоносную строку и идет проверка. 


Если Вам будет интересно посмотреть на другие тестовые задания выполненные в рамках SafeBoard, то это можно увидеть по ссылкам:

Разработка С:
https://github.com/tamchoor/C_TestTask
Программа по поиску файлов в каталоге с поддержкой WildCard.

Разработка С/С++:
https://github.com/tamchoor/C_CPP_TestTask
Создание сервер-клиент и логирование взаимодействия клиента с сервером.

Разработка С/С++:
https://github.com/tamchoor/C_CPP2_TESTTASK
Программа для вывода на консоль содержимого в каталоге и дочерних каталогах.


Стандартная версия задания

Задание:

Требуется реализовать утилиту, работающую из командной строки, для Linux или macOS, выполняющую сканирование файлов в директории, с целью нахождение в ней “подозрительных” (suspicious) файлов. 

 

В рамках задачи определено 3 типа “подозрительного” содержимого в файле.

JS suspicious: файл с расширением .js, содержащий строку: <script>evil_script()</script>
Unix suspicious: любой файл, содержащий строку: rm -rf ~/Documents
macOS suspicious: любой файл, содержащий строку: system("launchctl load /Library/LaunchAgents/com.malware.agent")
После завершения выполнения утилиты пользователю должен быть выведен отчет о сканировании, в котором присутствует следующая информация:

общее количество обработанных файлов;
количество детектов на каждый тип “подозрительного” содержимого;
количество ошибок анализа файлов (например, не хватает прав на чтение файла);
время выполнения утилиты.
Пример исполнения утилиты из командной строки:

$ ./scan_util /Users/user/Downloads

====== Scan result ======

Processed files: 150

JS detects: 5

Unix detects: 1

macOS detects: 2

Errors: 1

Exection time: 00:00:31 

=========================

 

Для упрощения задачи условимся:

Путь к директории и имена файлов состоят только из ASCII символов;
В директории находятся только файлы, вложенных директорий нет;
В каждом файле присутствует только один тип  “подозрительного” содержимого.
Рекомендуется максимальное использования (утилизация) вычислительных ресурсов устройства, на котором выполняется утилита.

Задача может быть решена с помощью следующих языков программирования: C++, Swift, Objective-C. Лучше использовать тот язык программирования, который для вас комфортнее всего - не нужно пытаться решить задачу на Swift, если до этого вы его не изучали :)

Свое решение прикрепляйте в поле ответа ниже в виде ссылки либо архива с кодом.



Усложненная версия задания

Синим цветом обозначены ключевые изменения в условии задания по сравнению со стандартной версией

Требуется реализовать два приложения для Linux или macOS:

Сервисное приложение, ожидающее команд на сканирование файлов в директориях и выполняющее сканирование файлов в директориях, с целью нахождение в них “подозрительных” (suspicious) файлов;
Утилиту, работающую из командной строки, отправляющую сервисному приложению команду на сканирование файлов в указанной директории. 
В рамках задачи определено 3 типа “подозрительного” содержимого в файле.

JS suspicious: файл с расширением .js, содержащий строку: <script>evil_script()</script>
Unix suspicious: любой файл, содержащий строку: rm -rf ~/Documents
macOS suspicious: любой файл, содержащий строку: system("launchctl load /Library/LaunchAgents/com.malware.agent")
Утилита должна дожидаться выполнения отправленной команды и по её итогам утилита должна вывести пользователю отчет о сканировании, в котором присутствует следующая информация:

общее количество обработанных файлов;
количество детектов на каждый тип “подозрительного” содержимого;
количество ошибок анализа файлов (например, не хватает прав на чтение файла);
время выполнения утилиты.
 

Пример запуска сервера и исполнения утилиты из командной строки:

$ ./scan_service &

[1] 1234

== Scan service is started ==

 

$ ./scan_util /Users/user/Downloads

 

====== Scan result ======

Processed files: 150

JS detects: 5

Unix detects: 1

macOS detects: 2

Errors: 1

Exection time: 00:00:31 

=========================

 

Для упрощения задачи условимся:

Путь к директории и имена файлов состоят только из ASCII символов;
В директории находятся только файлы, вложенных директорий нет;
В каждом файле присутствует только один тип  “подозрительного” содержимого;
Утилита-клиент и сервер работают на одном и том же устройстве.
Рекомендуется максимальное использования (утилизация) вычислительных ресурсов устройства, на котором выполняется утилита.

Задача может быть решена с помощью следующих языков программирования: C++, Swift, Objective-C. Лучше использовать тот язык программирования, который для вас комфортнее всего - не нужно пытаться решить задачу на Swift, если до этого вы его не изучали :)

Свое решение прикрепляйте в поле ответа ниже в виде ссылки либо архива с кодом.
