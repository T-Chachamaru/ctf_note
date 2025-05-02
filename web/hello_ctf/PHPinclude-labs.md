Level1-PHP封装协议
file://
访问本地文件系统,只能以绝对路径访问,并且如果访问的文件中的内容符合PHP代码格式,则会被当做PHP代码来执行
allow_url_fopen:Off/On
allow_url_include:无

data://
访问数据流,如果传入的数据是PHP代码,则会执行代码,支持文本和base64形式
data://text/plain,<?php phpinfo();?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8
allow_url_fopen:On
allow_url_include:On

http://与https://
常规URL形式,允许通过HTTP1.0的GET方法以只读访问文件或资源,通常用于远程包含
allow_url_fopen:On
allow_url_include:On

php://
访问各个输入/输出流(I/O streams),PHP中最为复杂和强大的协议,常用的有以下几种
php://input - 可以访问请求的原始数据的只读流,在POST请求中访问POST的data部分,在enctype="multipart/form-data"的时候php://input是无效的。常用于执行代码。 
allow_url_include:On
php://filter - (PHP_Version>=5.0.0)其参数会在该协议路径上进行传递,多个参数都可以在一个路径上传递,从而组成一个过滤链,常用于数据读取,在特殊情况下,利用特性还可以实现代码执行。无依赖,但在过滤链的代码执行中php://temp可能需要allow_url_include:On

php://input
php://input做为include的直接参数时,php执行时会将post内容当作文件内容,要注意,php://input不支持post提交,其请求的参数格式是原生(Raw)的内容,无法使用hackbar提交,因为hackbar不支持raw方式

php://filter
filter的参数如下:
resource=<要过滤的数据流>  这个参数是必须的。它指定了你要筛选过滤的数据流。  resource=flag.php
read=<读链的筛选列表>  该参数可选。可以设定一个或多个过滤器名称,以管道符（|）分隔。  php://filter/read=A|B|C/resource=flag.php
write=<写链的筛选列表>  该参数可选。可以设定一个或多个过滤器名称,以管道符（|）分隔。  php://filter/write=A|B|C/resource=flag.php
<;两个链的筛选列表>  任何没有以read=或write=作前缀的筛选器列表会视情况应用于读或写链。  php://filter/A|B|C/resource=flag.php
常用字符串过滤器:
string.rot13  rot13变换
string.toupper  转大写字母
string.tolower  转小写字母
string.strip_tags  去除html、PHP语言标签(本特性已自 PHP 7.3.0 起废弃)
常用转换过滤器:
convert.base64-encode 和 convert.base64-decode
convert.quoted-printable-encode 和 convert.quoted-printable-decode
convert.iconv.*

Level2-文件系统函数
除了include文件包含类函数能够使用PHP的封装协议外,其他文件系统函数也可以使用封装协议,如
file_get_contents()
file_put_contents()