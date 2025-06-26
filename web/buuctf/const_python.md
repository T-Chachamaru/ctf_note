# const_python

### 1.白盒审计的python题目
![const_python 1](./images/const_python1.png)

### 2.访问/src查看源码，找到关键函数，可以看到要打python pickle，但禁止了一大堆函数，使用pker构造操作码
<a href="https://h4cking2thegate.github.io/posts/38618/index.html">pker使用说明</a>
![const_python 2](./images/const_python2.png)

### 3.根据题目说明，flag在根目录下，因此直接读取flag覆盖掉app.py即可
![const_python 3](./images/const_python3.png)
![const_python 4](./images/const_python4.png)

### 4.获得flag
![const_python 5](./images/const_python5.png)