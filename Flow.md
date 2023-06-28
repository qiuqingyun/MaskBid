## 公共参数

椭圆曲线上的点 $G$ 和 $H$。

## Setp 0

1. $U_A$ 选择 $x_A$，计算 $Y_A=x_A\cdot H$ 并发送给 $U_B$ 。
2. $U_B$ 选择 $x_B$，计算 $Y_B=x_B\cdot H$ 并发送给 $U_A$ 。
3. $U_A$ 和 $U_B$ 计算 $Y=Y_A + Y_B=(x_A+x_B)\cdot H$。

## Step 1 

$U_A$：

1. 将输入值 $a$ 转化为二进制串 $\{a_l,a_{l-1},...,a_2,a_1\}$。
2. 对于 $i\in[1,l]$：
   1. 计算 $E(a_i)=(C_{ai1},C_{ai2})=(a_i \cdot G + r_i \cdot Y,\ r_i \cdot H)$，其中 $r_i$ 为随机数，将其发送给 $U_B$。
   2. 计算 Proof 1：
      1. 生成随机数 $V_1,V_2$。
      2. 计算承诺 $t=V_1\cdot G+V_2\cdot Y$。
      3. 计算挑战 $C=Hash(t,Y,G,H)$。
      4. 计算响应 $S_1=V_1-C\cdot a_i$ 和 $S_2=V_2-C\cdot r_i$。
      5. 发送 $(t,S_1,S_2)$。
      6. $U_B$ 验证：
         1. 计算挑战 $C=Hash(t,Y,G,H)$。
         2.  $G\cdot S_1+Y\cdot S_2+C\cdot C_{ai1}=t$。
   3. 计算 Proof 2：
      1. 生成随机数 $V$。
      2. 计算承诺 $t=V\cdot H$。
      3. 计算挑战 $C=Hash(t,C_{ai2},H)$。
      4. 计算响应 $S=V-C\cdot r_i$ 。
      5. 发送 $(t,S)$。
      6. $U_B$ 验证：
         1. 计算挑战 $C=Hash(t,C_{ai2},H)$。
         2.  $H\cdot S+C\cdot C_{ai2}=t$。
   4. 计算 Proof 3：
      1. 计算 $X=a_i \cdot G + r_i \cdot Y + r_i \cdot H$。
      2. 生成随机数 $V_1,V_2,V_3$，满足 $V_2-V_3=0$。
      3. 计算承诺 $t=V_1 \cdot G + V_2 \cdot Y + V_3 \cdot H$。
      4. 计算挑战 $C=Hash(t,X,Y,G,H)$。
      5. 计算响应 $S_1=V_1 - C \cdot a_i$，$S_2=V_2 - C \cdot r_i$ 和 $S_3=V_3 - C \cdot r_i$ 
      6. 发送 $(t,X,S_1,S_2,S_3)$。
      7. $U_B$ 验证：
         1. 计算挑战 $C=Hash(t,X,Y,G,H)$。
         2.  $G\cdot S_1+Y\cdot S_2+H\cdot S_3+C\cdot X=t$。
         3.  $S_2=S_3$。
   5. 计算 Proof 4：
      1. 计算 $X=r_i \cdot Y - R_i\cdot H$，其中 $R_i$ 为随机数。
      2. 生成随机数 $V_1,V_2$。
      3. 计算承诺 $t=V_1\cdot Y+V_2\cdot H$。
      4. 计算挑战 $C=Hash(t,X,Y,G,H)$。
      5. 计算响应 $S_1=V_1-C\cdot r_i$ 和 $S_2=V_2+C\cdot R_i$。
      6. 发送 $(t,X,S_1,S_2)$。
      7. $U_B$ 验证：
         1. 计算挑战 $C=Hash(t,X,Y,G,H)$。
         2.  $S_1\cdot Y+S_2\cdot H+C\cdot X=t$。

$U_B$：

1. 将输入值 $b$ 转化为二进制串 $\{b_l,b_{l-1},...,b_2,b_1\}$。
2. 对于 $i\in[1,l]$：
   1. 计算 $E(b_i)=(C_{bi1},C_{bi2})=(b_i \cdot G + r_i \cdot Y,\ r_i \cdot H)$，其中 $r_i$ 为随机数，将其发送给 $U_A$。
   2. 计算 Proof 5：
      1. 生成随机数 $V_1,V_2$。
      2. 计算承诺 $t=V_1\cdot G+V_2\cdot Y$。
      3. 计算挑战 $C=Hash(t,Y,G,H)$。
      4. 计算响应 $S_1=V_1-C\cdot b_i$ 和 $S_2=V_2-C\cdot r_i$。
      5. 发送 $(t,S_1,S_2)$。
      6. $U_A$ 验证：
         1. 计算挑战 $C=Hash(t,Y,G,H)$。
         2.  $G\cdot S_1+Y\cdot S_2+C\cdot C_{bi1}=t$。
   3. 计算 Proof 6：
      1. 生成随机数 $V$。
      2. 计算承诺 $t=V\cdot H$。
      3. 计算挑战 $C=Hash(t,C_{bi2},H)$。
      4. 计算响应 $S=V-C\cdot r_i$ 。
      5. 发送 $(t,S)$。
      6. $U_A$ 验证：
         1. 计算挑战 $C=Hash(t,C_{bi2},H)$。
         2.  $H\cdot S+C\cdot C_{bi2}=t$。
   4. 计算 Proof 7：
      1. 计算 $X=b_i \cdot G + r_i \cdot Y + r_i \cdot H$。
      2. 生成随机数 $V_1,V_2,V_3$，满足 $V_2-V_3=0$。
      3. 计算承诺 $t=V_1 \cdot G + V_2 \cdot Y + V_3 \cdot H$。
      4. 计算挑战 $C=Hash(t,X,Y,G,H)$。
      5. 计算响应 $S_1=V_1 - C \cdot b_i$，$S_2=V_2 - C \cdot r_i$ 和 $S_3=V_3 - C \cdot r_i$ 
      6. 发送 $(t,X,S_1,S_2,S_3)$。
      7. $U_A$ 验证：
         1. 计算挑战 $C=Hash(t,X,Y,G,H)$。
         2.  $G\cdot S_1+Y\cdot S_2+H\cdot S_3+C\cdot X=t$
         3.  $S_2=S_3$
   5. 计算 Proof 8：
      1. 计算 $X=r_i \cdot Y - R_i\cdot H$，其中 $R_i$ 为随机数。
      2. 生成随机数 $V_1,V_2$。
      3. 计算承诺 $t=V_1\cdot Y+V_2\cdot H$。
      4. 计算挑战 $C=Hash(t,X,Y,G,H)$。
      5. 计算响应 $S_1=V_1-C\cdot r_i$ 和 $S_2=V_2+C\cdot R_i$。
      6. 发送 $(t,X,S_1,S_2)$。
      7. $U_A$ 验证：
         1. 计算挑战 $C=Hash(t,X,Y,G,H)$。
         2.  $S_1\cdot Y+S_2\cdot H+C\cdot X=t$。

## Step 2

$U_A$：

1. 对于 $i\in[1,l]$：
   1. 计算 $ρ=t_i \cdot r_i$，其中 $t_i$ 为随机数。
   2. 计算 $E(v_i) = (C_{vi1},C_{vi2}) = a_i \cdot E(b_i) + E(0,ρ)$，将其发送给 $U_B$。
   3. 计算 Proof 12：
      1. 计算 $X=C_{vi1} + a_i \cdot G + R_i\cdot H$，其中 $R_i$ 为随机数。
      2. 生成随机数 $V_1,V_2,V_3,V_4$，满足 $V_1-V_3=0$。
      3. 计算承诺 $t=V_1 \cdot C_{bi1} + V_2 \cdot Y + V_3 \cdot G + V_4 \cdot H$。
      4. 计算挑战 $C=Hash(t,X,Y,G,H)$。
      5. 计算响应：
         1.  $S_1=V_1-C\cdot a_i$ 
         2.  $S_2=V_2-C\cdot ρ$ 
         3.  $S_3=V_3-C\cdot a_i$ 
         4.  $S_2=V_4-C\cdot R_i$ 
      6. 发送 $(t,S_1,S_2,S_3,S_4)$。
      7. $U_B$ 验证：
         1. 计算挑战 $C=Hash(t,X,Y,G,H)$。
         2.  $S_1 \cdot C_{bi1} + S_2\cdot Y + S_3\cdot G + S_4 \cdot H + X\cdot C=t$ 
         3.  $S_1=S_3$ 

## Step 3

$U_A$：

1. 对于 $i\in[1,l]$，计算 $E(W_i)=E(a_i)-E(b_i)+E(1)+\sum^l_{j=i+1}(E(a_j)+E(b_j)-2\cdot E(v_j))$。
2. 选择一个包含整数 $[1,l]$ 的数组 $\pi$，并将其洗牌。
3. 置换数组 $E(W)$，将每个 $E(W_i)$ 置换为 $E(W_{\pi_i})=(c_1,c_2)$，最后将得到的数组 $E(W')$ 发送给 $U_B$。
4. 选择 $l$ 个随机数 $\{u_1,u_2,...,u_l\}$。
5. 对于 $i\in[1,l]$，计算 $E(\delta_i)=u_i\cdot E(W_{\pi_i})=(C_1,C_2)$，最后将数组 $E(\delta)$ 发送给 $U_B$。
6. 计算 Proof 13：
   1. 选择 $l$ 个随机数 $\{\rho_1,\rho_2,...,\rho_l\}$。
   2. 选择 $l$ 个随机数 $\{s_1,s_2,...,s_l\}$。
   3. 选择 $l$ 个随机数 $\{t_1,t_2,...,t_l\}$。
   4. 对于 $j\in[1,l]$ ：
      1. 计算 $C'_j=E(0,\rho_j)+E(W_{\pi_i})$。
      2. 计算 $C_{A_j}=\pi_j\cdot G+s_j\cdot H$。
   5. 计算 $x=Hash(C_{A},Y,G,H)$。
   6. 对于 $j\in[1,l]$ ：
      1. 计算 $B_j=x^{\pi_j}$。
      2. 计算 $C_{B_j}=B_j\cdot G+t_j\cdot H$。
   7. 计算 $y=Hash(1,C_{B},Y,G,H)$。
   8. 计算 $z=Hash(2,C_{B},Y,G,H)$。
   9. 设置 $E=1$。
   10. 对于 $j\in[1,l]$ ：
       1. 计算 $D'_j=B_j+y\cdot \pi_j-z$。
       2. 计算 $C_{D'_j}=D'_j\cdot G+(y\cdot s_j+t_j)\cdot H$。
       3. 计算 $E=E\cdot D'_j$。
   11. 计算 $\rho'=-\sum^l_{j=1}\rho_j\cdot B_j$。
   12. 计算 $F=E(0,\rho')+\sum^l_{j=1}B_j\cdot C'_j$。
   13. 发送$\{(C_{A_j},C_{B_j},C_{D'_j})\}_{j\in[1,m]}$，标量$E$ 和密文 $F$。
   14. $U_B$ 验证：
       1. 计算 $x=Hash(C_{A},Y,G,H)$。
       2. 计算 $y=Hash(1,C_{B},Y,G,H)$。
       3. 计算 $z=Hash(2,C_{B},Y,G,H)$。
       4. 对于 $j\in[1,l]$ ，计算 $C_{D_j}=y\cdot C_{A_j}+C_{B_j}-z\cdot G$。
       5. 验证向量 $C_{D'}=C_{D}$。
       6. 验证 $E=\prod^l_{j=1}(x^j+y\cdot j-z)$。
       7. 验证 $F=\sum^l_{j=1}C'_j\cdot x^j$。
7. 计算 Proof 14：
   1. 生成随机数 $V$。
   2. 计算承诺 $t_1=c_1\cdot V$，$t_2=c_2\cdot V$。
   3. 计算挑战 $C=Hash(t_1,t_2,c_1,c_2,Y,G,H)$。
   4. 计算响应 $S=V-C\cdot u_i$。
   5. 发送 $(t_1,t_2,S)$。
   6. $U_B$ 验证：
      1. 计算挑战 $C=Hash(t_1,t_2,c_1,c_2,Y,G,H)$。
      2.  $S\cdot c_1+C\cdot C_1=t_1$。
      3.  $S\cdot c_2+C\cdot C_2=t_2$。

## Step 4

$U_B$：

1. 选择一个包含整数 $[1,l]$ 的数组 $\pi'$，并将其洗牌。
2. 置换收到的数组 $E(\delta)$，将每个 $E(\delta_i)$ 置换为 $E(\delta_{\pi_i})=(c_1,c_2)$，最后将得到的数组 $E(\delta')$ 发送给 $U_A$。
3. 选择 $l$ 个随机数 $\{v_1,v_2,...,v_l\}$。
4. 对于 $i\in[1,l]$，计算 $E(\sigma_i)=v_i\cdot E(\delta_{\pi_i})=(C_1,C_2)$，最后将数组 $E(\sigma)$ 发送给 $U_A$。
5. 计算 Proof 15：
   1. 选择 $l$ 个随机数 $\{\rho_1,\rho_2,...,\rho_l\}$。
   2. 选择 $l$ 个随机数 $\{s_1,s_2,...,s_l\}$。
   3. 选择 $l$ 个随机数 $\{t_1,t_2,...,t_l\}$。
   4. 对于 $j\in[1,l]$ ：
      1. 计算 $C'_j=E(0,\rho_j)+E(\delta_{\pi_i})$。
      2. 计算 $C_{A_j}=\pi'_j\cdot G+s_j\cdot H$。
   5. 计算 $x=Hash(C_{A_1},Y,G,H)$。
   6. 对于 $j\in[1,l]$ ：
      1. 计算 $B_j=x^{\pi'_j}$。
      2. 计算 $C_{B_j}=B_j\cdot G+t_j\cdot H$。
   7. 计算 $y=Hash(1,C_{B},Y,G,H)$。
   8. 计算 $z=Hash(2,C_{B},Y,G,H)$。
   9. 设置 $E=1$。
   10. 对于 $j\in[1,l]$ ：
       1. 计算 $D'_j=B_j+y\cdot \pi'_j-z$。
       2. 计算 $C_{D'_j}=D'_j\cdot G+(y\cdot s_j+t_j)\cdot H$。
       3. 计算 $E=E\cdot D'_j$。
   11. 计算 $\rho'=-\sum^l_{j=1}\rho_j\cdot B_j$。
   12. 计算 $F=E(0,\rho')+\sum^l_{j=1}B_j\cdot C'_j$。
   13. 发送$\{(C_{A_j},C_{B_j},C_{D'_j})\}_{j\in[1,m]}$，标量$E$ 和密文 $F$。
   14. $U_B$ 验证：
       1. 计算 $x=Hash(C_{A_1},Y,G,H)$。
       2. 计算 $y=Hash(1,C_{B},Y,G,H)$。
       3. 计算 $z=Hash(2,C_{B},Y,G,H)$。
       4. 对于 $j\in[1,l]$ ，计算 $C_{D_j}=y\cdot C_{A_j}+C_{B_j}-z\cdot G$。
       5. 验证向量 $C_{D'}=C_{D}$。
       6. 验证 $E=\prod^l_{j=1}(x^j+y\cdot j-z)$。
       7. 验证 $F=\sum^l_{j=1}C'_j\cdot x^j$。
6. 计算 Proof 16：
   1. 生成随机数 $V$。
   2. 计算承诺 $t_1=c_1\cdot V$，$t_2=c_2\cdot V$。
   3. 计算挑战 $C=Hash(t_1,t_2,c_1,c_2,Y,G,H)$。
   4. 计算响应 $S=V-C\cdot v_i$。
   5. 发送 $(t_1,t_2,S)$。
   6. $U_A$ 验证：
      1. 计算挑战 $C=Hash(t_1,t_2,c_1,c_2,Y,G,H)$。
      2.  $S\cdot c_1+C\cdot C_1=t_1$。
      3.  $S\cdot c_2+C\cdot C_2=t_2$。

## Step 5

$U_A$：

1. 对于 $i\in[1,l]$：
   1. 令  $E(\sigma_i)=(C_{i1},C_{i2})$。
   2. 计算 $\alpha_i= x_A\cdot C_{i2}$，将其发送给 $U_B$。
   3. 计算 Proof 17：
      1. 生成随机数 $V$。
      2. 计算承诺 $t_1=V\cdot C_{i2}$，$t_2=V\cdot H$。
      3. 计算挑战 $C=Hash(t_1,t_2,\alpha_i,Y_A,Y,G,H)$。
      4. 计算响应 $S=V-C\cdot x_A$。
      5. 发送 $(t_1,t_2,S)$。
      6. $U_B$ 验证：
         1. 计算挑战 $C=Hash(t_1,t_2,\alpha_i,Y_A,Y,G,H)$。
         2.  $S\cdot C_{i2}+C\cdot \alpha_i=t_1$。
         3.  $S\cdot H+C\cdot Y_A=t_2$。

## Step 6

$U_B$：

1. 对于 $i\in[1,l]$：
   1. 令  $E(\sigma_i)=(C_{i1},C_{i2})$。
   2. 计算 $\beta_i= x_B\cdot C_{i2}$，将其发送给 $U_A$。
   3. 计算 Proof 17：
      1. 生成随机数 $V$。
      2. 计算承诺 $t_1=V\cdot C_{i2}$，$t_2=V\cdot H$。
      3. 计算挑战 $C=Hash(t_1,t_2,\beta_i,Y_B,Y,G,H)$。
      4. 计算响应 $S=V-C\cdot x_B$。
      5. 发送 $(t_1,t_2,S)$。
      6. $U_A$ 验证：
         1. 计算挑战 $C=Hash(t_1,t_2,\beta_i,Y_B,Y,G,H)$。
         2.  $S\cdot C_{i2}+C\cdot \beta_i=t_1$。
         3.  $S\cdot H+C\cdot Y_B=t_2$。

## Step 7

对于 $i\in[1,l]$，计算 $A_i=C_{i1}-(\alpha_i+\beta_i)$，若有任意 $A_i=G$，则 $a< b$，否则 $a\ge b$。