#include "base.h"
#include "ElGamal.h"
#include "hash.h"

// 设置全局变量l为32
const int l = 32;

// 将BIGNUM转化为二进制序列
std::vector<int> BN_to_binary_sequence(BIGNUM *input)
{
    std::vector<int> binary_sequence;
    for (int i = 0; i < l; ++i)
    {
        binary_sequence.push_back(BN_is_bit_set(input, i));
    }
    // 反转input_a_binary
    std::reverse(binary_sequence.begin(), binary_sequence.end());
    return binary_sequence;
}

int proof_shuffle(std::vector<ElGamal_ciphertext *> *C, int pi[], W1 &w1, BN_CTX *ctx)
{
    // 选择 l 个随机数 {ρ1,ρ2,...,ρl}
    std::vector<BIGNUM *> rho;
    // 选择 l 个随机数 {s1,s2,...,sl}
    std::vector<BIGNUM *> s;
    // 选择 l 个随机数 {t1,t2,...,tl}
    std::vector<BIGNUM *> t;
    for (int j = 0; j < l; ++j)
    {
        rho.push_back(BN_rand(256));
        s.push_back(BN_rand(256));
        t.push_back(BN_rand(256));
    }
    // 保存向量π
    BIGNUM *BN_pi[l];
    // 保存向量C'
    ElGamal_ciphertext *C_prime[l];
    // 保存向量CA
    EC_POINT *C_A[l];
    BIGNUM *BN_zero = BN_new();
    BN_set_word(BN_zero, 0);
    for (int j = 0; j < l; ++j)
    {
        // 生成 E(0,ρj)
        ElGamal_ciphertext *E_0_rho_j = ElGamal_encrypt(&w1, BN_zero, rho[j], ctx);
        // 计算 C'j = E(0,ρj) + C[πj]
        C_prime[j] = new ElGamal_ciphertext;
        ElGamal_add(w1.get_curve(), C_prime[j], E_0_rho_j, C->at(pi[j] - 1), ctx); // E(0,ρj) + C[πj]
        // 将πj转化为BIGNUM
        BN_pi[j] = BN_new();
        BN_set_word(BN_pi[j], pi[j]);
        // 计算 CAj = πj*G + sj*H
        C_A[j] = EC_POINT_new(w1.get_curve());
        EC_POINT *temp = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), BN_pi[j], ctx); // πj*G
        EC_POINT_mul(w1.get_curve(), C_A[j], NULL, w1.get_H(), s[j], ctx);   // sj*H
        EC_POINT_add(w1.get_curve(), C_A[j], temp, C_A[j], ctx);             // πj*G + sj*H
        // 释放内存
        delete E_0_rho_j;
        EC_POINT_free(temp);
    }
    // 将CA串联成字符串
    std::stringstream CA_ss;
    for (int j = 0; j < l; ++j)
    {
        CA_ss << EC_POINT_point2hex(w1.get_curve(), C_A[j], POINT_CONVERSION_COMPRESSED, ctx);
    }
    // 计算 x=Hash(CA, w1)
    BIGNUM *x = BN_hash(CA_ss.str(), w1.to_string(ctx));
    // 保存向量B
    BIGNUM *B[l];
    // 保存向量CB
    EC_POINT *CB[l];
    for (int j = 0; j < l; ++j)
    {
        // 计算 Bj = x^{πj}
        B[j] = BN_new();
        BN_mod_exp(B[j], x, BN_pi[j], w1.get_order(), ctx);
        // 计算 CBj = Bj*G + tj*H
        CB[j] = EC_POINT_new(w1.get_curve());
        EC_POINT *temp = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), B[j], ctx);  // Bj*G
        EC_POINT_mul(w1.get_curve(), CB[j], NULL, w1.get_H(), t[j], ctx); // tj*H
        EC_POINT_add(w1.get_curve(), CB[j], temp, CB[j], ctx);            // Bj*G + tj*H
        // 释放内存
        EC_POINT_free(temp);
    }
    // 将CB串联成字符串
    std::stringstream CB_ss;
    for (int j = 0; j < l; ++j)
    {
        CB_ss << EC_POINT_point2hex(w1.get_curve(), CB[j], POINT_CONVERSION_COMPRESSED, ctx);
    }
    // 计算 y = Hash(1, CB, w1)
    BIGNUM *y = BN_hash("1", CB_ss.str(), w1.to_string(ctx));
    // 计算 z = Hash(2, CB, w1)
    BIGNUM *z = BN_hash("2", CB_ss.str(), w1.to_string(ctx));
    // 设置 E = 1
    BIGNUM *E = BN_new();
    BN_one(E);
    // 保存向量CD'
    EC_POINT *CD_prime[l];
    for (int j = 0; j < l; ++j)
    {
        // 计算 Dj' = Bj + y*πj - z
        BIGNUM *D_prime_j = BN_new();
        BN_mod_mul(D_prime_j, y, BN_pi[j], w1.get_order(), ctx);     // y*πj
        BN_mod_sub(D_prime_j, D_prime_j, z, w1.get_order(), ctx);    // y*πj - z
        BN_mod_add(D_prime_j, D_prime_j, B[j], w1.get_order(), ctx); // Bj + y*πj - z
        // 计算 CDj' = Dj'*G + (y*sj + tj)*H
        CD_prime[j] = EC_POINT_new(w1.get_curve());
        EC_POINT *temp = EC_POINT_new(w1.get_curve());
        BIGNUM *y_sj = BN_new();
        BIGNUM *y_sj_tj = BN_new();
        EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), D_prime_j, ctx);      // Dj'*G
        BN_mod_mul(y_sj, y, s[j], w1.get_order(), ctx);                            // y*sj
        BN_mod_add(y_sj_tj, y_sj, t[j], w1.get_order(), ctx);                      // y*sj + tj
        EC_POINT_mul(w1.get_curve(), CD_prime[j], NULL, w1.get_H(), y_sj_tj, ctx); // (y*sj + tj)*H
        EC_POINT_add(w1.get_curve(), CD_prime[j], temp, CD_prime[j], ctx);         // Dj'*G + (y*sj + tj)*H
        // 累乘 E = E*Dj'
        BN_mod_mul(E, E, D_prime_j, w1.get_order(), ctx);
        // 释放内存
        BN_free(D_prime_j);
        BN_free(y_sj);
        BN_free(y_sj_tj);
        EC_POINT_free(temp);
    }
    // 计算 ⍴' = -(⍴1*B1 + ⍴2*B2 + ... + ⍴l*Bl)
    BIGNUM *rho_prime = BN_new();
    BN_zero(rho_prime);
    for (int j = 0; j < l; ++j)
    {
        BIGNUM *rho_prime_j = BN_new();
        BN_mod_mul(rho_prime_j, rho[j], B[j], w1.get_order(), ctx);         // ⍴j*Bj
        BN_mod_add(rho_prime, rho_prime, rho_prime_j, w1.get_order(), ctx); // ⍴' = ⍴' + ⍴j*Bj
        // 释放内存
        BN_free(rho_prime_j);
    }
    BN_mod_sub(rho_prime, w1.get_order(), rho_prime, w1.get_order(), ctx); // ⍴' = -⍴'
    // 计算 F = E(0,⍴') + B1*C1' + B2*C2' + ... + Bl*Cl'
    ElGamal_ciphertext *F = new ElGamal_ciphertext(w1.get_curve(), w1.get_Y(), w1.get_H());
    ElGamal_mul(w1.get_curve(), F, F, rho_prime, ctx);
    for (int j = 0; j < l; ++j)
    {
        ElGamal_ciphertext *temp_F = new ElGamal_ciphertext;
        ElGamal_mul(w1.get_curve(), temp_F, C_prime[j], B[j], ctx); // Bj*Cj'
        ElGamal_add(w1.get_curve(), F, F, temp_F, ctx);             // F = F + Bj*Cj'
        // 释放内存
        delete temp_F;
    }
    // 验证证明
    // 保存CD的比较结果
    bool result_CD = true;
    // 保存 E' = (x^1 + y*1 - z) * (x^2 + y*2 - z) * ... * (x^m + y*m - z)
    BIGNUM *E_prime = BN_new();
    BN_one(E_prime);
    // 验证 F = C1*x^1 + C2*x^2 + ... + Cm*x^m，赋值 F' = C1*x^1
    ElGamal_ciphertext *F_prime = new ElGamal_ciphertext(w1.get_curve(), C->at(0));
    ElGamal_mul(w1.get_curve(), F_prime, F_prime, x, ctx);
    for (int j = 0; j < l; ++j)
    {
        // 将j转换为BIGNUM
        BIGNUM *j_bn = BN_new();
        BN_set_word(j_bn, j + 1);
        // 计算 CDj = y*CAj + CBj - z*G
        EC_POINT *CDj = EC_POINT_new(w1.get_curve());
        EC_POINT *temp = EC_POINT_new(w1.get_curve());
        EC_POINT *temp_2 = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), temp, NULL, C_A[j], y, ctx);       // y*CAj
        EC_POINT_add(w1.get_curve(), temp, temp, CB[j], ctx);           // y*CAj + CBj
        EC_POINT_mul(w1.get_curve(), temp_2, NULL, w1.get_G(), z, ctx); // z*G
        EC_POINT_sub(w1.get_curve(), CDj, temp, temp_2, ctx);           // y*CAj + CBj - z*G
        // 比较CD'j和CDj
        result_CD &= (EC_POINT_cmp(w1.get_curve(), CD_prime[j], CDj, ctx) == 0);
        // 验证 E = (x^1 + y*1 - z) * (x^2 + y*2 - z) * ... * (x^m + y*m - z)
        BIGNUM *temp_x_j = BN_new();
        BIGNUM *temp1 = BN_new();
        BIGNUM *temp2 = BN_new();
        BN_mod_exp(temp_x_j, x, j_bn, w1.get_order(), ctx);      // x^j
        BN_mod_mul(temp1, y, j_bn, w1.get_order(), ctx);         // y*j
        BN_mod_add(temp2, temp1, temp_x_j, w1.get_order(), ctx); // x^j + y*j
        BN_mod_sub(temp2, temp2, z, w1.get_order(), ctx);        // x^j + y*j - z

        // 累乘 E' = E' * (x^j + y*j - z)
        BN_mod_mul(E_prime, E_prime, temp2, w1.get_order(), ctx);
        // 累加 F' = F' + Cj*x^j
        if (j > 0)
        {
            // 计算 Cj*x^j
            ElGamal_ciphertext *temp_c = new ElGamal_ciphertext();
            ElGamal_mul(w1.get_curve(), temp_c, C->at(j), temp_x_j, ctx); // Cj*x^j
            // 累加 F' = F' + C'j*x^j
            ElGamal_add(w1.get_curve(), F_prime, F_prime, temp_c, ctx);
            // 释放内存
            BN_free(temp_x_j);
            delete temp_c;
        }
        // 释放内存
        BN_free(j_bn);
        EC_POINT_free(CDj);
        EC_POINT_free(temp);
        EC_POINT_free(temp_2);
        BN_free(temp1);
        BN_free(temp2);
    }
    // 比较CD'和CD
    if (!result_CD)
    {
        std::cout << "proof 13 failed: CD" << std::endl;
        return -1;
    }
    // 比较 E 和 E'
    if (BN_cmp(E, E_prime) != 0)
    {
        std::cout << "proof 13 failed: E'" << std::endl;
        return -2;
    }
    // 比较 F 和 F'
    if (EC_POINT_cmp(w1.get_curve(), F->C1, F_prime->C1, ctx) != 0 || EC_POINT_cmp(w1.get_curve(), F->C2, F_prime->C2, ctx) != 0)
    {
        std::cout << "proof 13 failed: F" << std::endl;
        return -3;
    }
    // 释放内存
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(E);
    BN_free(E_prime);
    BN_free(rho_prime);
    delete F;
    delete F_prime;
    for (int j = 0; j < l; ++j)
    {
        BN_free(rho[j]);
        BN_free(s[j]);
        BN_free(t[j]);
        BN_free(B[j]);
        BN_free(BN_pi[j]);
        delete C_prime[j];
        EC_POINT_free(C_A[j]);
        EC_POINT_free(CB[j]);
        EC_POINT_free(CD_prime[j]);
    }
    return 0;
}

int main()
{
    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    std::random_device rd;
    unsigned char seed[256];
    for (size_t i = 0; i < sizeof(seed); ++i)
    {
        seed[i] = static_cast<unsigned char>(rd());
    }
    RAND_seed(seed, sizeof(seed));
    BN_CTX *ctx = BN_CTX_new();

    /* Global */
    W1 w1(ctx); // 公共参数

    // 公用的BIGNUM
    BIGNUM *BN_zero = BN_new();
    BIGNUM *BN_one = BN_new();
    BIGNUM *BN_two = BN_new();
    BN_set_word(BN_zero, 0);
    BN_set_word(BN_one, 1);
    BN_set_word(BN_two, 2);

    /* SETP 0 */
    // UA和UB的密钥
    BIGNUM *x_a, *x_b;
    // UA和UB的公钥
    EC_POINT *y_a, *y_b;
    // 获取UA和UB的密钥对
    ElGamal_keygen(&w1, &y_a, &x_a, ctx);
    ElGamal_keygen(&w1, &y_b, &x_b, ctx);

    // UA和UB的联合公钥
    EC_POINT *Y = EC_POINT_new(w1.get_curve());
    EC_POINT_add(w1.get_curve(), Y, y_a, y_b, ctx);
    w1.set_Y(Y);

    /* STEP 1 */
    // 随机生成输入a和b
    BIGNUM *input_a = BN_rand(32);
    BIGNUM *input_b = BN_rand(32);

    // 输入a和b
    // BIGNUM *input_a = BN_new();
    // BIGNUM *input_b = BN_new();
    // BN_dec2bn(&input_a, "9");
    // BN_dec2bn(&input_b, "10");

    // 打印输入a和b
    std::cout << "a: " << BN_bn2dec(input_a) << std::endl;
    std::cout << "b: " << BN_bn2dec(input_b) << std::endl;

    // 保存比较结果
    std::string result_plaintext = BN_cmp(input_a, input_b) < 0 ? "<" : ">=";
    std::string result_cipher = ">=";
    // 将a和b转化为二进制序列
    std::vector<int> a_binary_list = BN_to_binary_sequence(input_a);
    std::vector<int> b_binary_list = BN_to_binary_sequence(input_b);
    // 加密UA和UB的二进制序列
    std::vector<BIGNUM *> a, b, r;
    std::vector<ElGamal_ciphertext *> E_a, E_b;
    // UA
    for (int i = 0; i < l; ++i)
    {
        // 生成加密ai的随机数ri
        BIGNUM *ri = BN_rand(256);
        // 加密ai
        BIGNUM *ai = (a_binary_list[i] == 0 ? BN_zero : BN_one);
        ElGamal_ciphertext *E_ai = ElGamal_encrypt(&w1, ai, ri, ctx);
        a.push_back(ai);
        r.push_back(ri);
        E_a.push_back(E_ai);

        /* proof 1 */
        {
            // 生成随机数 V1,V2
            BIGNUM *V1 = BN_rand(256);
            BIGNUM *V2 = BN_rand(256);
            // 计算承诺 t = V1*G + V2*Y
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), V1, ctx); // V1*G
            EC_POINT_mul(w1.get_curve(), t, NULL, w1.get_Y(), V2, ctx);    // V2*Y
            EC_POINT_add(w1.get_curve(), t, temp, t, ctx);                 // V1*G + V2*Y
            // 计算挑战 C = H(t, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                w1.to_string(ctx));
            // 计算响应 S1 = V1 - c*ai
            BIGNUM *S1 = BN_new();
            BN_mod_mul(S1, C, ai, w1.get_order(), ctx);  // C*ai
            BN_mod_sub(S1, V1, S1, w1.get_order(), ctx); // V1 - C*ai
            // 计算响应 S2 = V2 - c*ri
            BIGNUM *S2 = BN_new();
            BN_mod_mul(S2, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S2, V2, S2, w1.get_order(), ctx); // V2 - C*ri
            // 验证证明
            // 计算承诺 t' = S1*G + S2*Y + C*E(ai).C1
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), S1, ctx); // S1*G
            EC_POINT_mul(w1.get_curve(), t_prime, NULL, w1.get_Y(), S2, ctx);    // S2*Y
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, t_prime, ctx);     // S1*G + S2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, E_ai->C1, C, ctx);  // C*E(ai).C1
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_2, ctx);   // S1*G + S2*Y + C*E(ai).C1
            // 验证 t' = t
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0)
            {
                std::cout << "proof 1 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V1);
            BN_free(V2);
            BN_free(C);
            BN_free(S1);
            BN_free(S2);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp);
            EC_POINT_free(temp_prime);
            EC_POINT_free(temp_prime_2);
        }
        /* proof 2 */
        {
            // 生成随机数 V
            BIGNUM *V = BN_rand(256);
            // 计算承诺 t = V*H
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t, NULL, w1.get_H(), V, ctx); // V*H
            // 计算挑战 C = H(t, E(ai).C2, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                EC_POINT_to_string(w1.get_curve(), E_ai->C2, ctx),
                w1.to_string(ctx));
            // 计算响应 S = V - C*ri
            BIGNUM *S = BN_new();
            BN_mod_mul(S, C, ri, w1.get_order(), ctx); // C*ri
            BN_mod_sub(S, V, S, w1.get_order(), ctx);  // V - C*ri
            // 验证证明
            // 计算承诺 t' = S*H + C*E(ai).C2
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_H(), S, ctx); // S*H
            EC_POINT_mul(w1.get_curve(), t_prime, NULL, E_ai->C2, C, ctx);      // C*E(ai).C2
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, t_prime, ctx);    // S*H + C*E(ai).C2
            // 验证 t' = t
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0)
            {
                std::cout << "proof 2 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V);
            BN_free(C);
            BN_free(S);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp_prime);
        }
        /* proof 3 */
        {
            // 计算 X = ai*G + ri*Y + ri*H
            EC_POINT *X = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), ai, ctx);   // ai*G
            EC_POINT_mul(w1.get_curve(), temp_2, NULL, w1.get_Y(), ri, ctx); // ri*Y
            EC_POINT_add(w1.get_curve(), temp, temp, temp_2, ctx);           // ai*G + ri*Y
            EC_POINT_mul(w1.get_curve(), X, NULL, w1.get_H(), ri, ctx);      // ri*H
            EC_POINT_add(w1.get_curve(), X, temp, X, ctx);                   // ai*G + ri*Y + ri*H
            // 生成随机数 V1,V2,V3，满足 V2-V3=0
            BIGNUM *V1 = BN_rand(256);
            BIGNUM *V2 = BN_rand(256);
            BIGNUM *V3 = BN_dup(V2);
            // 计算承诺 t = V1*G + V2*Y + V3*H
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), V1, ctx);   // V1*G
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_Y(), V2, ctx); // V2*Y
            EC_POINT_add(w1.get_curve(), t, temp_prime, temp_prime_2, ctx);        // V1*G + V2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_H(), V3, ctx);   // V3*H
            EC_POINT_add(w1.get_curve(), t, t, temp_prime, ctx);                   // V1*G + V2*Y + V3*H
            // 计算挑战 C = H(t, X, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                EC_POINT_to_string(w1.get_curve(), X, ctx),
                w1.to_string(ctx));
            // 计算响应 S1 = V1 - C*ai
            BIGNUM *S1 = BN_new();
            BN_mod_mul(S1, C, ai, w1.get_order(), ctx);  // C*ai
            BN_mod_sub(S1, V1, S1, w1.get_order(), ctx); // V1 - C*ai
            // 计算响应 S2 = V2 - C*ri
            BIGNUM *S2 = BN_new();
            BN_mod_mul(S2, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S2, V2, S2, w1.get_order(), ctx); // V2 - C*ri
            // 计算响应 S3 = V3 - C*ri
            BIGNUM *S3 = BN_new();
            BN_mod_mul(S3, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S3, V3, S3, w1.get_order(), ctx); // V3 - C*ri
            // 验证证明
            // 计算承诺 t' = S1*G + S2*Y + S3*H + C*X
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_3 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_4 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_5 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), S1, ctx);   // S1*G
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_Y(), S2, ctx); // S2*Y
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, temp_prime_2, ctx);  // S1*G + S2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime_3, NULL, w1.get_H(), S3, ctx); // S3*H
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_3, ctx);     // S1*G + S2*Y + S3*H
            EC_POINT_mul(w1.get_curve(), temp_prime_4, NULL, X, C, ctx);           // C*X
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_4, ctx);     // S1*G + S2*Y + S3*H + C*X
            // 验证 t' = t 和 S2 = S3
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0 || BN_cmp(S2, S3) != 0)
            {
                std::cout << "proof 3 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                // 打印S2和S3
                std::cout << "S2 = " << BN_bn2dec(S2) << std::endl;
                std::cout << "S3 = " << BN_bn2dec(S3) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V1);
            BN_free(V2);
            BN_free(V3);
            BN_free(C);
            BN_free(S1);
            BN_free(S2);
            BN_free(S3);
            EC_POINT_free(X);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp);
            EC_POINT_free(temp_2);
            EC_POINT_free(temp_prime);
            EC_POINT_free(temp_prime_2);
            EC_POINT_free(temp_prime_3);
            EC_POINT_free(temp_prime_4);
            EC_POINT_free(temp_prime_5);
        }
        /* proof 4 */
        {
            // 计算 X = ri*Y - Ri*H，其中 Ri 为随机数
            BIGNUM *Ri = BN_rand(256);
            EC_POINT *X = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_Y(), ri, ctx);   // ri*Y
            EC_POINT_mul(w1.get_curve(), temp_2, NULL, w1.get_H(), Ri, ctx); // Ri*H
            EC_POINT_sub(w1.get_curve(), X, temp, temp_2, ctx);              // ri*Y - Ri*H
            // 生成随机数 V1,V2
            BIGNUM *V1 = BN_rand(256);
            BIGNUM *V2 = BN_rand(256);
            // 计算承诺 t = V1*Y + V2*H
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_Y(), V1, ctx);   // V1*Y
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_H(), V2, ctx); // V2*H
            EC_POINT_add(w1.get_curve(), t, temp_prime, temp_prime_2, ctx);        // V1*Y + V2*H
            // 计算挑战 C = H(t, X, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                EC_POINT_to_string(w1.get_curve(), X, ctx),
                w1.to_string(ctx));
            // 计算响应 S1 = V1 - C*ri
            BIGNUM *S1 = BN_new();
            BN_mod_mul(S1, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S1, V1, S1, w1.get_order(), ctx); // V1 - C*ri
            // 计算响应 S2 = V2 + C*Ri
            BIGNUM *S2 = BN_new();
            BN_mod_mul(S2, C, Ri, w1.get_order(), ctx);  // C*Ri
            BN_mod_add(S2, V2, S2, w1.get_order(), ctx); // V2 + C*Ri
            // 验证证明
            // 计算承诺 t' = S1*Y + S2*H + C*X
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_3 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_4 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_5 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_Y(), S1, ctx);   // S1*Y
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_H(), S2, ctx); // S2*H
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, temp_prime_2, ctx);  // S1*Y + S2*H
            EC_POINT_mul(w1.get_curve(), temp_prime_3, NULL, X, C, ctx);           // C*X
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_3, ctx);     // S1*Y + S2*H + C*X
            // 验证 t' = t
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0)
            {
                std::cout << "proof 4 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(Ri);
            BN_free(V1);
            BN_free(V2);
            BN_free(C);
            BN_free(S1);
            BN_free(S2);
            EC_POINT_free(X);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp);
            EC_POINT_free(temp_2);
            EC_POINT_free(temp_prime);
            EC_POINT_free(temp_prime_2);
            EC_POINT_free(temp_prime_3);
            EC_POINT_free(temp_prime_4);
            EC_POINT_free(temp_prime_5);
        }
    }
    // UB
    for (int i = 0; i < l; ++i)
    {
        // 生成加密bi的随机数ri
        BIGNUM *ri = BN_rand(256);
        // 加密bi
        BIGNUM *bi = (b_binary_list[i] == 0 ? BN_zero : BN_one);
        ElGamal_ciphertext *E_bi = ElGamal_encrypt(&w1, bi, ri, ctx);
        b.push_back(bi);
        E_b.push_back(E_bi);

        /* proof 5 */
        {
            // 生成随机数 V1,V2
            BIGNUM *V1 = BN_rand(256);
            BIGNUM *V2 = BN_rand(256);
            // 计算承诺 t = V1*G + V2*Y
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), V1, ctx); // V1*G
            EC_POINT_mul(w1.get_curve(), t, NULL, w1.get_Y(), V2, ctx);    // V2*Y
            EC_POINT_add(w1.get_curve(), t, temp, t, ctx);                 // V1*G + V2*Y
            // 计算挑战 C = H(t, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                w1.to_string(ctx));
            // 计算响应 S1 = V1 - C*bi
            BIGNUM *S1 = BN_new();
            BN_mod_mul(S1, C, bi, w1.get_order(), ctx);  // C*bi
            BN_mod_sub(S1, V1, S1, w1.get_order(), ctx); // V1 - C*bi
            // 计算响应 S2 = V2 - C*ri
            BIGNUM *S2 = BN_new();
            BN_mod_mul(S2, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S2, V2, S2, w1.get_order(), ctx); // V2 - C*ri
            // 验证证明
            // 计算承诺 t' = S1*G + S2*Y + C*E(bi).C1
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), S1, ctx); // S1*G
            EC_POINT_mul(w1.get_curve(), t_prime, NULL, w1.get_Y(), S2, ctx);    // S2*Y
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, t_prime, ctx);     // S1*G + S2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, E_bi->C1, C, ctx);  // C*E(bi).C1
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_2, ctx);   // S1*G + S2*Y + C*E(bi).C1
            // 验证 t' = t
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0)
            {
                std::cout << "proof 5 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V1);
            BN_free(V2);
            BN_free(C);
            BN_free(S1);
            BN_free(S2);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp);
            EC_POINT_free(temp_prime);
            EC_POINT_free(temp_prime_2);
        }
        /* proof 6 */
        {
            // 生成随机数 V
            BIGNUM *V = BN_rand(256);
            // 计算承诺 t = V*H
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t, NULL, w1.get_H(), V, ctx); // V*H
            // 计算挑战 C = H(t, E(bi).C2, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                EC_POINT_to_string(w1.get_curve(), E_bi->C2, ctx),
                w1.to_string(ctx));
            // 计算响应 S = V - C*ri
            BIGNUM *S = BN_new();
            BN_mod_mul(S, C, ri, w1.get_order(), ctx); // C*ri
            BN_mod_sub(S, V, S, w1.get_order(), ctx);  // V - C*ri
            // 验证证明
            // 计算承诺 t' = S*H + C*E(bi).C2
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_H(), S, ctx); // S*H
            EC_POINT_mul(w1.get_curve(), t_prime, NULL, E_bi->C2, C, ctx);      // C*E(bi).C2
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, t_prime, ctx);    // S*H + C*E(bi).C2
            // 验证 t' = t
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0)
            {
                std::cout << "proof 6 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V);
            BN_free(C);
            BN_free(S);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp_prime);
        }
        /* proof 7 */
        {
            // 计算 X = bi*G + ri*Y + ri*H
            EC_POINT *X = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), bi, ctx);   // bi*G
            EC_POINT_mul(w1.get_curve(), temp_2, NULL, w1.get_Y(), ri, ctx); // ri*Y
            EC_POINT_add(w1.get_curve(), temp, temp, temp_2, ctx);           // bi*G + ri*Y
            EC_POINT_mul(w1.get_curve(), X, NULL, w1.get_H(), ri, ctx);      // ri*H
            EC_POINT_add(w1.get_curve(), X, temp, X, ctx);                   // bi*G + ri*Y + ri*H
            // 生成随机数 V1,V2,V3，满足 V2-V3=0
            BIGNUM *V1 = BN_rand(256);
            BIGNUM *V2 = BN_rand(256);
            BIGNUM *V3 = BN_dup(V2);
            // 计算承诺 t = V1*G + V2*Y + V3*H
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), V1, ctx);   // V1*G
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_Y(), V2, ctx); // V2*Y
            EC_POINT_add(w1.get_curve(), t, temp_prime, temp_prime_2, ctx);        // V1*G + V2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_H(), V3, ctx);   // V3*H
            EC_POINT_add(w1.get_curve(), t, t, temp_prime, ctx);                   // V1*G + V2*Y + V3*H
            // 计算挑战 C = H(t, X, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                EC_POINT_to_string(w1.get_curve(), X, ctx),
                w1.to_string(ctx));
            // 计算响应 S1 = V1 - C*bi
            BIGNUM *S1 = BN_new();
            BN_mod_mul(S1, C, bi, w1.get_order(), ctx);  // C*bi
            BN_mod_sub(S1, V1, S1, w1.get_order(), ctx); // V1 - C*bi
            // 计算响应 S2 = V2 - C*ri
            BIGNUM *S2 = BN_new();
            BN_mod_mul(S2, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S2, V2, S2, w1.get_order(), ctx); // V2 - C*ri
            // 计算响应 S3 = V3 - C*ri
            BIGNUM *S3 = BN_new();
            BN_mod_mul(S3, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S3, V3, S3, w1.get_order(), ctx); // V3 - C*ri
            // 验证证明
            // 计算承诺 t' = S1*G + S2*Y + S3*H + C*X
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_3 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_4 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_5 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), S1, ctx);   // S1*G
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_Y(), S2, ctx); // S2*Y
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, temp_prime_2, ctx);  // S1*G + S2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime_3, NULL, w1.get_H(), S3, ctx); // S3*H
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_3, ctx);     // S1*G + S2*Y + S3*H
            EC_POINT_mul(w1.get_curve(), temp_prime_4, NULL, X, C, ctx);           // C*X
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_4, ctx);     // S1*G + S2*Y + S3*H + C*X
            // 验证 t' = t 和 S2 = S3
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0 || BN_cmp(S2, S3) != 0)
            {
                std::cout << "proof 7 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                // 打印S2和S3
                std::cout << "S2 = " << BN_bn2dec(S2) << std::endl;
                std::cout << "S3 = " << BN_bn2dec(S3) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V1);
            BN_free(V2);
            BN_free(V3);
            BN_free(C);
            BN_free(S1);
            BN_free(S2);
            BN_free(S3);
            EC_POINT_free(X);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp);
            EC_POINT_free(temp_2);
            EC_POINT_free(temp_prime);
            EC_POINT_free(temp_prime_2);
            EC_POINT_free(temp_prime_3);
            EC_POINT_free(temp_prime_4);
            EC_POINT_free(temp_prime_5);
        }
        /* proof 8 */
        {
            // 计算 X = ri*Y - Ri*H，其中 Ri 为随机数
            BIGNUM *Ri = BN_rand(256);
            EC_POINT *X = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_Y(), ri, ctx);   // ri*Y
            EC_POINT_mul(w1.get_curve(), temp_2, NULL, w1.get_H(), Ri, ctx); // Ri*H
            EC_POINT_sub(w1.get_curve(), X, temp, temp_2, ctx);              // ri*Y - Ri*H
            // 生成随机数 V1,V2
            BIGNUM *V1 = BN_rand(256);
            BIGNUM *V2 = BN_rand(256);
            // 计算承诺 t = V1*Y + V2*H
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_Y(), V1, ctx);   // V1*Y
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_H(), V2, ctx); // V2*H
            EC_POINT_add(w1.get_curve(), t, temp_prime, temp_prime_2, ctx);        // V1*Y + V2*H
            // 计算挑战 C = H(t, X, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                EC_POINT_to_string(w1.get_curve(), X, ctx),
                w1.to_string(ctx));
            // 计算响应 S1 = V1 - C*ri
            BIGNUM *S1 = BN_new();
            BN_mod_mul(S1, C, ri, w1.get_order(), ctx);  // C*ri
            BN_mod_sub(S1, V1, S1, w1.get_order(), ctx); // V1 - C*ri
            // 计算响应 S2 = V2 + C*Ri
            BIGNUM *S2 = BN_new();
            BN_mod_mul(S2, C, Ri, w1.get_order(), ctx);  // C*Ri
            BN_mod_add(S2, V2, S2, w1.get_order(), ctx); // V2 + C*Ri
            // 验证证明
            // 计算承诺 t' = S1*Y + S2*H + C*X
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_3 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_4 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_Y(), S1, ctx); // S1*Y
            EC_POINT_mul(w1.get_curve(), t_prime, NULL, w1.get_H(), S2, ctx);    // S2*H
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, t_prime, ctx);     // S1*Y + S2*H
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, X, C, ctx);         // C*X
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_2, ctx);   // S1*Y + S2*H + C*X
            // 验证 t' = t
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0)
            {
                std::cout << "proof 8 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(Ri);
            BN_free(V1);
            BN_free(V2);
            BN_free(C);
            BN_free(S1);
            BN_free(S2);
            EC_POINT_free(X);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp);
            EC_POINT_free(temp_2);
            EC_POINT_free(temp_prime);
            EC_POINT_free(temp_prime_2);
            EC_POINT_free(temp_prime_3);
            EC_POINT_free(temp_prime_4);
        }
    }

    /* STEP 2 */
    std::vector<ElGamal_ciphertext *> E_v;
    for (int i = 0; i < l; ++i)
    {
        // 生成随机数ti
        BIGNUM *t_i = BN_rand(256);
        // 计算ρ = ti * ri
        BIGNUM *rho = BN_new();
        BN_mod_mul(rho, t_i, r[i], w1.get_order(), ctx);
        // 计算E(0,ρ)
        ElGamal_ciphertext *E_0_rho = ElGamal_encrypt(&w1, BN_zero, rho, ctx);
        // 计算E(vi) = ai * E(bi)
        ElGamal_ciphertext *E_vi = new ElGamal_ciphertext;
        ElGamal_mul(w1.get_curve(), E_vi, E_b[i], a[i], ctx);
        // 计算E(vi) = ai * E(bi) + E(0,ρ)
        ElGamal_add(w1.get_curve(), E_vi, E_vi, E_0_rho, ctx);
        E_v.push_back(E_vi);

        /* proof 12 */
        {
            // 计算 X = E(vi).C1 + ai*G + Ri*H，其中 Ri 为随机数
            BIGNUM *Ri = BN_rand(256);
            EC_POINT *X = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G(), a[i], ctx); // ai*G
            EC_POINT_mul(w1.get_curve(), temp_2, NULL, w1.get_H(), Ri, ctx); // Ri*H
            EC_POINT_add(w1.get_curve(), temp, temp, temp_2, ctx);           // ai*G + Ri*H
            EC_POINT_add(w1.get_curve(), X, E_vi->C1, temp, ctx);            // E(vi).C1 + ai*G + Ri*H
            // 生成随机数 V1,V2,V3,V4，满足 V1-V3=0
            BIGNUM *V1 = BN_rand(256);
            BIGNUM *V2 = BN_rand(256);
            BIGNUM *V3 = BN_dup(V1);
            BIGNUM *V4 = BN_rand(256);
            // 计算承诺 t = V1*E(bi).C1 + V2*Y + V3*G + V4*H
            EC_POINT *t = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_2 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_3 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, E_b[i]->C1, V1, ctx);   // V1*E(bi).C1
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_Y(), V2, ctx); // V2*Y
            EC_POINT_add(w1.get_curve(), t, temp_prime, temp_prime_2, ctx);        // V1*E(bi).C1 + V2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), V3, ctx);   // V3*G
            EC_POINT_add(w1.get_curve(), t, t, temp_prime, ctx);                   // V1*E(bi).C1 + V2*Y + V3*G
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_H(), V4, ctx);   // V4*H
            EC_POINT_add(w1.get_curve(), t, t, temp_prime, ctx);                   // V1*E(bi).C1 + V2*Y + V3*G + V4*H
            // 计算挑战 C = H(t, X, W1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t, ctx),
                EC_POINT_to_string(w1.get_curve(), X, ctx),
                w1.to_string(ctx));
            // 计算响应 S1 = V1 - C*ai
            BIGNUM *S1 = BN_new();
            BN_mod_mul(S1, C, a[i], w1.get_order(), ctx); // C*ai
            BN_mod_sub(S1, V1, S1, w1.get_order(), ctx);  // V1 - C*ai
            // 计算响应 S2 = V2 - C*ρ
            BIGNUM *S2 = BN_new();
            BN_mod_mul(S2, C, rho, w1.get_order(), ctx); // C*ρ
            BN_mod_sub(S2, V2, S2, w1.get_order(), ctx); // V2 - C*ρ
            // 计算响应 S3 = V3 - C*ai
            BIGNUM *S3 = BN_new();
            BN_mod_mul(S3, C, a[i], w1.get_order(), ctx); // C*ai
            BN_mod_sub(S3, V3, S3, w1.get_order(), ctx);  // V3 - C*ai
            // 计算响应 S4 = V4 - C*Ri
            BIGNUM *S4 = BN_new();
            BN_mod_mul(S4, C, Ri, w1.get_order(), ctx);  // C*Ri
            BN_mod_sub(S4, V4, S4, w1.get_order(), ctx); // V4 - C*Ri
            // 验证证明
            // 计算承诺 t' = S1*E(bi).C1 + S2*Y + S3*G + S4*H + C*X
            EC_POINT *t_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_4 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_5 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp_prime_6 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, E_b[i]->C1, S1, ctx);   // S1*E(bi).C1
            EC_POINT_mul(w1.get_curve(), temp_prime_2, NULL, w1.get_Y(), S2, ctx); // S2*Y
            EC_POINT_add(w1.get_curve(), t_prime, temp_prime, temp_prime_2, ctx);  // S1*E(bi).C1 + S2*Y
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_G(), S3, ctx);   // S3*G
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime, ctx);       // S1*E(bi).C1 + S2*Y + S3*G
            EC_POINT_mul(w1.get_curve(), temp_prime, NULL, w1.get_H(), S4, ctx);   // S4*H
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime, ctx);       // S1*E(bi).C1 + S2*Y + S3*G + S4*H
            EC_POINT_mul(w1.get_curve(), temp_prime_3, NULL, X, C, ctx);           // C*X
            EC_POINT_add(w1.get_curve(), t_prime, t_prime, temp_prime_3, ctx);     // S1*E(bi).C1 + S2*Y + S3*G + S4*H + C*X
            // 验证 t' = t 和 S1 = S3
            if (EC_POINT_cmp(w1.get_curve(), t_prime, t, ctx) != 0 || BN_cmp(S1, S3) != 0)
            {
                std::cout << "proof 12 failed" << std::endl;
                // 打印t'和t
                std::cout << "t' = " << EC_POINT_point2hex(w1.get_curve(), t_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t  = " << EC_POINT_point2hex(w1.get_curve(), t, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                // 打印S2和S3
                std::cout << "S1 = " << BN_bn2dec(S1) << std::endl;
                std::cout << "S3 = " << BN_bn2dec(S3) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(Ri);
            BN_free(V1);
            BN_free(V2);
            BN_free(V3);
            BN_free(V4);
            BN_free(C);
            BN_free(S1);
            BN_free(S2);
            BN_free(S3);
            BN_free(S4);
            EC_POINT_free(X);
            EC_POINT_free(t);
            EC_POINT_free(t_prime);
            EC_POINT_free(temp);
            EC_POINT_free(temp_2);
            EC_POINT_free(temp_prime);
            EC_POINT_free(temp_prime_2);
            EC_POINT_free(temp_prime_3);
            EC_POINT_free(temp_prime_4);
            EC_POINT_free(temp_prime_5);
            EC_POINT_free(temp_prime_6);
        }
    }

    /* STEP 3 */
    std::vector<ElGamal_ciphertext *> E_W, E_w;
    ElGamal_ciphertext *ElGamal_one = ElGamal_encrypt(&w1, BN_one, ctx); // E(1)
    for (int i = 0; i < l; ++i)
    {
        // 计算 E(Wi) = E(ai) - E(bi) + E(1) + (E(a1) + E(b1) - 2*E(vj)) + (E(a2) + E(b2) - 2*E(v2)) + ... + (E(a(i-1)) + E(b(i-1)) - 2*E(v(i-1)))
        ElGamal_ciphertext *E_Wi = new ElGamal_ciphertext;
        ElGamal_sub(w1.get_curve(), E_Wi, E_a[i], E_b[i], ctx);    // E(ai) - E(bi)
        ElGamal_add(w1.get_curve(), E_Wi, E_Wi, ElGamal_one, ctx); // E(ai) - E(bi) + E(1)

        ElGamal_ciphertext *E_sum = ElGamal_encrypt(&w1, BN_zero, ctx);

        ElGamal_ciphertext *E_2vj = new ElGamal_ciphertext;
        ElGamal_ciphertext *temp = new ElGamal_ciphertext;
        ElGamal_add(w1.get_curve(), temp, E_a[i], E_b[i], ctx);  // E(aj) + E(bj)
        ElGamal_mul(w1.get_curve(), E_2vj, E_v[i], BN_two, ctx); // 2*E(vj)
        ElGamal_sub(w1.get_curve(), E_2vj, temp, E_2vj, ctx);    // E(aj) + E(bj) - 2*E(vj)
        E_w.push_back(E_2vj);
        for (int j = 0; j < i; ++j)
        {
            ElGamal_add(w1.get_curve(), E_sum, E_sum, E_w[j], ctx); // 累加
        }
        ElGamal_add(w1.get_curve(), E_Wi, E_Wi, E_sum, ctx); // E(ai) - E(bi) + E(1) + (E(aj) + E(bj) - 2*E(vj))
        E_W.push_back(E_Wi);
    }
    // 选择一个包含从1到l所有整数的数组π，并将其顺序shuffle
    int pi[l];
    for (int i = 0; i < l; ++i)
    {
        pi[i] = i + 1;
    }
    // 使用std::shuffle对数组π进行随机排序
    std::shuffle(pi, pi + l, std::default_random_engine(std::random_device()()));
    // 生成置换后的数组 E(W')
    std::vector<ElGamal_ciphertext *> E_W_prime;
    // 生成l个随机数 {u1,u2,...,ul}
    std::vector<BIGNUM *> u;
    std::vector<ElGamal_ciphertext *> E_delta;
    for (int i = 0; i < l; ++i)
    {
        E_W_prime.push_back(E_W[pi[i] - 1]);
        u.push_back(BN_rand(256));
        // 计算 E(δi) = ui * E(W'i)
        ElGamal_ciphertext *E_delta_i = new ElGamal_ciphertext;
        ElGamal_mul(w1.get_curve(), E_delta_i, E_W_prime[i], u[i], ctx);
        E_delta.push_back(E_delta_i);
    }
    /* proof 13 */
    int result_13 = proof_shuffle(&E_W_prime, pi, w1, ctx);
    if (result_13 != 0)
    {
        std::cout << "proof 13 failed" << std::endl;
        return 0;
    }

    /* proof 14 */
    {
        for (int i = 0; i < l; ++i)
        {
            // 生成随机数 V
            BIGNUM *V = BN_rand(256);
            // 计算承诺 t1 = E(W'i).C1*V
            EC_POINT *t1 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t1, NULL, E_W_prime[i]->C1, V, ctx);
            // 计算承诺 t2 = E(W'i).C2*V
            EC_POINT *t2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t2, NULL, E_W_prime[i]->C2, V, ctx);
            // 计算挑战 C = Hash(t1, t2, E(W'i).C1, E(W'i).C2,w1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t1, ctx),
                EC_POINT_to_string(w1.get_curve(), t2, ctx),
                EC_POINT_to_string(w1.get_curve(), E_W_prime[i]->C1, ctx),
                EC_POINT_to_string(w1.get_curve(), E_W_prime[i]->C2, ctx),
                w1.to_string(ctx));
            // 计算响应 S = V - C*ui
            BIGNUM *S = BN_new();
            BN_mod_mul(S, C, u[i], w1.get_order(), ctx); // C*ui
            BN_mod_sub(S, V, S, w1.get_order(), ctx);    // V - C*ui
            // 验证证明
            // 计算承诺 t1' = S*E(W'i).C1 + C*E(δi).C1
            EC_POINT *t1_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, E_W_prime[i]->C1, S, ctx);   // S*E(W'i).C1
            EC_POINT_mul(w1.get_curve(), t1_prime, NULL, E_delta[i]->C1, C, ctx); // C*E(δi).C1
            EC_POINT_add(w1.get_curve(), t1_prime, temp, t1_prime, ctx);          // S*E(W'i).C1 + C*E(δi).C1
            // 计算承诺 t2' = S*E(W'i).C2 + C*E(δi).C2
            EC_POINT *t2_prime = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, E_W_prime[i]->C2, S, ctx);   // S*E(W'i).C2
            EC_POINT_mul(w1.get_curve(), t2_prime, NULL, E_delta[i]->C2, C, ctx); // C*E(δi).C2
            EC_POINT_add(w1.get_curve(), t2_prime, temp, t2_prime, ctx);          // S*E(W'i).C2 + C*E(δi).C2
            // 验证 t1' = t1 和 t2' = t2
            if (EC_POINT_cmp(w1.get_curve(), t1_prime, t1, ctx) != 0 || EC_POINT_cmp(w1.get_curve(), t2_prime, t2, ctx) != 0)
            {
                std::cout << "proof 14 failed" << std::endl;
                // 打印t1'和t1
                std::cout << "t1' = " << EC_POINT_point2hex(w1.get_curve(), t1_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t1  = " << EC_POINT_point2hex(w1.get_curve(), t1, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                // 打印t2'和t2
                std::cout << "t2' = " << EC_POINT_point2hex(w1.get_curve(), t2_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t2  = " << EC_POINT_point2hex(w1.get_curve(), t2, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V);
            BN_free(C);
            BN_free(S);
            EC_POINT_free(t1);
            EC_POINT_free(t2);
            EC_POINT_free(t1_prime);
            EC_POINT_free(t2_prime);
            EC_POINT_free(temp);
        }
    }

    /* STEP 4 */
    // 选择一个包含从1到l所有整数的数组π'，并将其顺序shuffle
    int pi_prime[l];
    for (int i = 0; i < l; ++i)
    {
        pi_prime[i] = i + 1;
    }
    // 使用std::shuffle对数组π'进行随机排序
    std::shuffle(pi_prime, pi_prime + l, std::default_random_engine(std::random_device()()));
    // 生成置换后的数组 E(δ')
    std::vector<ElGamal_ciphertext *> E_delta_prime;
    // 生成l个随机数 {v1,v2,...,vl}
    std::vector<BIGNUM *> v;
    std::vector<ElGamal_ciphertext *> E_sigma;
    for (int i = 0; i < l; ++i)
    {
        E_delta_prime.push_back(E_delta[pi_prime[i] - 1]);
        v.push_back(BN_rand(256));
        // 计算 E(σi) = vi * E(δ'i)
        ElGamal_ciphertext *E_sigma_i = new ElGamal_ciphertext;
        ElGamal_mul(w1.get_curve(), E_sigma_i, E_delta_prime[i], v[i], ctx);
        E_sigma.push_back(E_sigma_i);
    }

    /* proof 15 */
    int result_15 = proof_shuffle(&E_delta_prime, pi_prime, w1, ctx);
    if (result_15 != 0)
    {
        std::cout << "proof 15 failed" << std::endl;
        return 0;
    }

    /* proof 16 */
    {
        for (int i = 0; i < l; ++i)
        {
            // 生成随机数 V
            BIGNUM *V = BN_rand(256);
            // 计算承诺 t1 = E(δ'i).C1*V
            EC_POINT *t1 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t1, NULL, E_delta_prime[i]->C1, V, ctx);
            // 计算承诺 t2 = E(δ'i).C2*V
            EC_POINT *t2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t2, NULL, E_delta_prime[i]->C2, V, ctx);
            // 计算挑战 C = Hash(t1, t2, E(δ'i).C1, E(δ'i).C2,w1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t1, ctx),
                EC_POINT_to_string(w1.get_curve(), t2, ctx),
                EC_POINT_to_string(w1.get_curve(), E_delta_prime[i]->C1, ctx),
                EC_POINT_to_string(w1.get_curve(), E_delta_prime[i]->C2, ctx),
                w1.to_string(ctx));
            // 计算响应 S = V - C*vi
            BIGNUM *S = BN_new();
            BN_mod_mul(S, C, v[i], w1.get_order(), ctx); // C*vi
            BN_mod_sub(S, V, S, w1.get_order(), ctx);    // V - C*vi
            // 验证证明
            // 计算承诺 t1' = S*E(δ'i).C1 + C*E(σi).C1
            EC_POINT *t1_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, E_delta_prime[i]->C1, S, ctx); // S*E(δ'i).C1
            EC_POINT_mul(w1.get_curve(), t1_prime, NULL, E_sigma[i]->C1, C, ctx);   // C*E(σi).C1
            EC_POINT_add(w1.get_curve(), t1_prime, temp, t1_prime, ctx);            // S*E(δ'i).C1 + C*E(σi).C1
            // 计算承诺 t2' = S*E(δ'i).C2 + C*E(σi).C2
            EC_POINT *t2_prime = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, E_delta_prime[i]->C2, S, ctx); // S*E(δ'i).C2
            EC_POINT_mul(w1.get_curve(), t2_prime, NULL, E_sigma[i]->C2, C, ctx);   // C*E(σi).C2
            EC_POINT_add(w1.get_curve(), t2_prime, temp, t2_prime, ctx);            // S*E(δ'i).C2 + C*E(σi).C2
            // 验证 t1' = t1 和 t2' = t2
            if (EC_POINT_cmp(w1.get_curve(), t1_prime, t1, ctx) != 0 || EC_POINT_cmp(w1.get_curve(), t2_prime, t2, ctx) != 0)
            {
                std::cout << "proof 16 failed" << std::endl;
                // 打印t1'和t1
                std::cout << "t1' = " << EC_POINT_point2hex(w1.get_curve(), t1_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t1  = " << EC_POINT_point2hex(w1.get_curve(), t1, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                // 打印t2'和t2
                std::cout << "t2' = " << EC_POINT_point2hex(w1.get_curve(), t2_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t2  = " << EC_POINT_point2hex(w1.get_curve(), t2, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V);
            BN_free(C);
            BN_free(S);
            EC_POINT_free(t1);
            EC_POINT_free(t2);
            EC_POINT_free(t1_prime);
            EC_POINT_free(t2_prime);
            EC_POINT_free(temp);
        }
    }

    /* STEP 5 */
    std::vector<EC_POINT *> alpha, beta;
    for (int i = 0; i < l; ++i)
    {
        // 计算 αi = x_A*E(σi)_2
        EC_POINT *alpha_i = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), alpha_i, NULL, E_sigma[i]->C2, x_a, ctx);
        alpha.push_back(alpha_i);

        /* proof 17 */
        {
            // 生成随机数 V
            BIGNUM *V = BN_rand(256);
            // 计算承诺 t1 = V*E(σi).C2
            EC_POINT *t1 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t1, NULL, E_sigma[i]->C2, V, ctx);
            // 计算承诺 t2 = V*H
            EC_POINT *t2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t2, NULL, w1.get_H(), V, ctx);
            // 计算挑战 C = Hash(t1, t2, αi, y_a,w1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t1, ctx),
                EC_POINT_to_string(w1.get_curve(), t2, ctx),
                EC_POINT_to_string(w1.get_curve(), alpha_i, ctx),
                EC_POINT_to_string(w1.get_curve(), y_a, ctx),
                w1.to_string(ctx));
            // 计算响应 S = V - C*x_a
            BIGNUM *S = BN_new();
            BN_mod_mul(S, C, x_a, w1.get_order(), ctx); // C*x_a
            BN_mod_sub(S, V, S, w1.get_order(), ctx);   // V - C*x_a
            // 验证证明
            // 计算承诺 t1' = S*E(σi).C2 + C*αi
            EC_POINT *t1_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, E_sigma[i]->C2, S, ctx); // S*E(σi).C2
            EC_POINT_mul(w1.get_curve(), t1_prime, NULL, alpha_i, C, ctx);    // C*αi
            EC_POINT_add(w1.get_curve(), t1_prime, temp, t1_prime, ctx);      // S*E(σi).C2 + C*αi
            // 计算承诺 t2' = S*H + C*y_a
            EC_POINT *t2_prime = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_H(), S, ctx); // S*H
            EC_POINT_mul(w1.get_curve(), t2_prime, NULL, y_a, C, ctx);    // C*y_a
            EC_POINT_add(w1.get_curve(), t2_prime, temp, t2_prime, ctx);  // S*H + C*y_a
            // 验证 t1' = t1 和 t2' = t2
            if (EC_POINT_cmp(w1.get_curve(), t1_prime, t1, ctx) != 0 || EC_POINT_cmp(w1.get_curve(), t2_prime, t2, ctx) != 0)
            {
                std::cout << "proof 17 failed" << std::endl;
                // 打印t1'和t1
                std::cout << "t1' = " << EC_POINT_point2hex(w1.get_curve(), t1_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t1  = " << EC_POINT_point2hex(w1.get_curve(), t1, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                // 打印t2'和t2
                std::cout << "t2' = " << EC_POINT_point2hex(w1.get_curve(), t2_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t2  = " << EC_POINT_point2hex(w1.get_curve(), t2, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V);
            BN_free(C);
            BN_free(S);
            EC_POINT_free(t1);
            EC_POINT_free(t2);
            EC_POINT_free(t1_prime);
            EC_POINT_free(t2_prime);
            EC_POINT_free(temp);
        }
    }

    /* STEP 6 */
    for (int i = 0; i < l; ++i)
    {
        // 计算 beta_i = x_B*E(σi)_2
        EC_POINT *beta_i = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), beta_i, NULL, E_sigma[i]->C2, x_b, ctx);
        beta.push_back(beta_i);

        /* proof 17 */
        {
            // 生成随机数 V
            BIGNUM *V = BN_rand(256);
            // 计算承诺 t1 = V*E(σi).C2
            EC_POINT *t1 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t1, NULL, E_sigma[i]->C2, V, ctx);
            // 计算承诺 t2 = V*H
            EC_POINT *t2 = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), t2, NULL, w1.get_H(), V, ctx);
            // 计算挑战 C = Hash(t1, t2, βi, y_b,w1)
            BIGNUM *C = BN_hash(
                EC_POINT_to_string(w1.get_curve(), t1, ctx),
                EC_POINT_to_string(w1.get_curve(), t2, ctx),
                EC_POINT_to_string(w1.get_curve(), beta_i, ctx),
                EC_POINT_to_string(w1.get_curve(), y_b, ctx),
                w1.to_string(ctx));
            // 计算响应 S = V - C*x_b
            BIGNUM *S = BN_new();
            BN_mod_mul(S, C, x_b, w1.get_order(), ctx); // C*x_b
            BN_mod_sub(S, V, S, w1.get_order(), ctx);   // V - C*x_b
            // 验证证明
            // 计算承诺 t1' = S*E(σi).C2 + C*βi
            EC_POINT *t1_prime = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, E_sigma[i]->C2, S, ctx); // S*E(σi).C2
            EC_POINT_mul(w1.get_curve(), t1_prime, NULL, beta_i, C, ctx);     // C*βi
            EC_POINT_add(w1.get_curve(), t1_prime, temp, t1_prime, ctx);      // S*E(σi).C2 + C*βi
            // 计算承诺 t2' = S*H + C*y_b
            EC_POINT *t2_prime = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_H(), S, ctx); // S*H
            EC_POINT_mul(w1.get_curve(), t2_prime, NULL, y_b, C, ctx);    // C*y_b
            EC_POINT_add(w1.get_curve(), t2_prime, temp, t2_prime, ctx);  // S*H + C*y_b
            // 验证 t1' = t1 和 t2' = t2
            if (EC_POINT_cmp(w1.get_curve(), t1_prime, t1, ctx) != 0 || EC_POINT_cmp(w1.get_curve(), t2_prime, t2, ctx) != 0)
            {
                std::cout << "proof 18 failed" << std::endl;
                // 打印t1'和t1
                std::cout << "t1' = " << EC_POINT_point2hex(w1.get_curve(), t1_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t1  = " << EC_POINT_point2hex(w1.get_curve(), t1, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                // 打印t2'和t2
                std::cout << "t2' = " << EC_POINT_point2hex(w1.get_curve(), t2_prime, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                std::cout << "t2  = " << EC_POINT_point2hex(w1.get_curve(), t2, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
                return 0;
            }
            // 释放内存
            BN_free(V);
            BN_free(C);
            BN_free(S);
            EC_POINT_free(t1);
            EC_POINT_free(t2);
            EC_POINT_free(t1_prime);
            EC_POINT_free(t2_prime);
            EC_POINT_free(temp);
        }
    }

    /* STEP 7 */
    for (int i = 0; i < l; ++i)
    {
        // 计算 A_i = E(σi)_1 - (alpha_i + beta_i)
        EC_POINT *A_i = EC_POINT_new(w1.get_curve());
        EC_POINT *temp_i = EC_POINT_new(w1.get_curve());
        EC_POINT_add(w1.get_curve(), temp_i, alpha[i], beta[i], ctx);
        EC_POINT_sub(w1.get_curve(), A_i, E_sigma[i]->C1, temp_i, ctx);

        // 判断是否有0
        if (EC_POINT_is_at_infinity(w1.get_curve(), A_i))
        {
            result_cipher = "<";
            break;
        }
    }
    std::cout << (result_plaintext == result_cipher ? "√" : "×") << ": a" << result_plaintext << "b" << std::endl;

    return 0;
}