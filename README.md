基于csapp书中分离适配描述的实现，测试成绩如下  
Results for mm malloc:  
trace  valid  util     ops      secs  Kops  
 0       yes   96%    5694  0.000201 28314  
 1       yes   94%    5848  0.000255 22942  
 2       yes   96%    6648  0.000394 16852  
 3       yes   95%    5380  0.000204 26424  
 4       yes   78%   14400  0.000260 55385  
 5       yes   87%    4800  0.000565  8503  
 6       yes   85%    4800  0.000632  7590  
 7       yes   61%   12000  0.007132  1683  
 8       yes   57%   24000  0.006841  3508  
 9       yes   89%   14401  0.030412   474  
10       yes   45%   14401  0.000999 14418  
Total          80%  112372  0.047894  2346  

Perf index = 48 (util) + 40 (thru) = 88/100  

建议在开始编写代码之前好好构思自己的数据结构，  
不然会像我一样重头来过。  
代码中对void* 指针的操作属于未定义行为，写到  
一半时意识到了问题如果要对 void 指针进行操作  
建议转换为char 指针  
