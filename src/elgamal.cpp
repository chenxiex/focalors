#include "focalors.h"
#include <gmp.h>
#include <gmpxx.h>
#include <string>
using std::string;

#ifdef DEBUG
#include <iostream>
#include <utility>
using std::cout;
using std::endl;
#endif

namespace elgamal
{
void find_primative_root(mpz_class &a, const mpz_class &p)
{
    for (mpz_class i(2); i < p; i++)
    {
        bool flag = true;
        for (mpz_class j(2); j < p - 1; j++)
        {
            if ((p - 1) % j == 0)
            {
                mpz_class temp;
                mpz_powm_sec(temp.get_mpz_t(), i.get_mpz_t(), j.get_mpz_t(), p.get_mpz_t());
                if (temp == 1)
                {
                    flag = false;
                    break;
                }
            }
        }
        if (flag)
        {
            a = i;
            return;
        }
    }
}
} // namespace elgamal

namespace focalors
{
void elgamal_generate_key(string &p, string &a, string &d, string &y, const int &base)
{
    mpz_class p_mpz, a_mpz, d_mpz, y_mpz;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomb(p_mpz.get_mpz_t(), state, 512);
    mpz_nextprime(p_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    elgamal::find_primative_root(a_mpz, p_mpz);
    mpz_class p_mpz_3 = p_mpz - 3;
    mpz_urandomm(d_mpz.get_mpz_t(), state, p_mpz_3.get_mpz_t());
    d_mpz += 2;
    mpz_powm_sec(y_mpz.get_mpz_t(), a_mpz.get_mpz_t(), d_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    p = p_mpz.get_str(base);
    a = a_mpz.get_str(base);
    d = d_mpz.get_str(base);
    y = y_mpz.get_str(base);
}
#ifdef DEBUG
void elgamal_generate_key(string &a, string &d, string &y, const string &p, const int &base)
{
    mpz_class p_mpz(p, base), a_mpz, d_mpz, y_mpz;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    elgamal::find_primative_root(a_mpz, p_mpz);
    mpz_class p_mpz_3 = p_mpz - 3;
    mpz_urandomm(d_mpz.get_mpz_t(), state, p_mpz_3.get_mpz_t());
    d_mpz += 2;
    mpz_powm_sec(y_mpz.get_mpz_t(), a_mpz.get_mpz_t(), d_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    a = a_mpz.get_str(base);
    d = d_mpz.get_str(base);
    y = y_mpz.get_str(base);
}
void elgamal_generate_key(string &y, const string &p, const string &a, const string &d, const int &base)
{
    mpz_class p_mpz(p, base), a_mpz(a), d_mpz(d), y_mpz;
    mpz_powm_sec(y_mpz.get_mpz_t(), a_mpz.get_mpz_t(), d_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    y = y_mpz.get_str(base);
}
#endif
void elgamal_encrypt(string &c1, string &c2, const string &m, const string &p, const string &a, const string &y,
                     const int &base)
{
    mpz_class c1_mpz, c2_mpz, m_mpz(m, base), p_mpz(p, base), a_mpz(a, base), y_mpz(y, base);
    mpz_class k;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_class p_mpz_3 = p_mpz - 3;
    mpz_urandomm(k.get_mpz_t(), state, p_mpz_3.get_mpz_t());
    k += 2;
    mpz_class u;
    mpz_powm_sec(u.get_mpz_t(), y_mpz.get_mpz_t(), k.get_mpz_t(), p_mpz.get_mpz_t());
    mpz_powm_sec(c1_mpz.get_mpz_t(), a_mpz.get_mpz_t(), k.get_mpz_t(), p_mpz.get_mpz_t());
    c2_mpz = (u * m_mpz);
    mpz_mod(c2_mpz.get_mpz_t(), c2_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    c1 = c1_mpz.get_str(base);
    c2 = c2_mpz.get_str(base);
}
#ifdef DEBUG
void elgamal_encrypt(string &c1, string &c2, const string &m, const string &p, const string &a, const string &y,
                     const string &k, const int &base)
{
    mpz_class c1_mpz, c2_mpz, m_mpz(m, base), p_mpz(p, base), a_mpz(a, base), y_mpz(y, base);
    mpz_class k_mpz(k, base);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_class u;
    mpz_powm_sec(u.get_mpz_t(), y_mpz.get_mpz_t(), k_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    mpz_powm_sec(c1_mpz.get_mpz_t(), a_mpz.get_mpz_t(), k_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    c2_mpz = (u * m_mpz);
    mpz_mod(c2_mpz.get_mpz_t(), c2_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    c1 = c1_mpz.get_str(base);
    c2 = c2_mpz.get_str(base);
}
#endif
void elgamal_decrypt(string &m, const string &c1, const string &c2, const string &d, const string &p, const int &base)
{
    mpz_class m_mpz, c1_mpz(c1, base), c2_mpz(c2, base), d_mpz(d, base), p_mpz(p, base);
    mpz_class v;
    mpz_powm_sec(v.get_mpz_t(), c1_mpz.get_mpz_t(), d_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    mpz_invert(v.get_mpz_t(), v.get_mpz_t(), p_mpz.get_mpz_t());
    m_mpz = (v * c2_mpz);
    mpz_mod(m_mpz.get_mpz_t(), m_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    m = m_mpz.get_str(base);
}
void elgamal_sign1(string &r, string &s, const string &m, const string &p, const string &a, const string &d,
                   const int &base)
{
    mpz_class r_mpz, s_mpz, k_mpz;
    mpz_class m_mpz(m, base), p_mpz(p, base), a_mpz(a, base), d_mpz(d, base);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_class p_mpz_3 = p_mpz - 3, p_mpz_1 = p_mpz - 1;
    mpz_class temp;
    do
    {
        mpz_urandomm(k_mpz.get_mpz_t(), state, p_mpz_3.get_mpz_t());
        k_mpz += 2;
        mpz_gcd(temp.get_mpz_t(), k_mpz.get_mpz_t(), p_mpz_1.get_mpz_t());
    } while (temp != 1);
    mpz_powm_sec(r_mpz.get_mpz_t(), a_mpz.get_mpz_t(), k_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    mpz_invert(k_mpz.get_mpz_t(), k_mpz.get_mpz_t(), p_mpz_1.get_mpz_t());
    temp=(m_mpz-d_mpz*r_mpz);
    s_mpz = (k_mpz * (m_mpz - d_mpz * r_mpz));
    mpz_mod(s_mpz.get_mpz_t(), s_mpz.get_mpz_t(), p_mpz_1.get_mpz_t());
    r = r_mpz.get_str(base);
    s = s_mpz.get_str(base);
}
bool elgamal_verify1(const string &m, const string &r, const string &s, const string &p, const string &a,
                     const string &y, const int &base)
{
    mpz_class m_mpz(m, base), r_mpz(r, base), s_mpz(s, base), p_mpz(p, base), a_mpz(a, base), y_mpz(y, base);
    mpz_class v1, v2;
    mpz_powm_sec(v1.get_mpz_t(), y_mpz.get_mpz_t(), r_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    mpz_powm_sec(v2.get_mpz_t(), r_mpz.get_mpz_t(), s_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    mpz_class v = (v1 * v2);
    mpz_mod(v.get_mpz_t(), v.get_mpz_t(), p_mpz.get_mpz_t());
    mpz_class am;
    mpz_powm_sec(am.get_mpz_t(), a_mpz.get_mpz_t(), m_mpz.get_mpz_t(), p_mpz.get_mpz_t());
    return v == am;
}
} // namespace focalors

#ifdef DEBUG
int main()
{
    string m = "14", k;
    string c1, c2;
    string p = "19", a, y, d;
    string decrypted;
    focalors::elgamal_generate_key(a, d, y, std::move(p), 10);
    cout << "a=" << a << "\nd=" << d << "\ny=" << y << endl;
    focalors::elgamal_sign1(c1, c2, m, p, a, d, 10);
    cout << "c1=" << c1 << "\nc2=" << c2 << endl;
    bool flag = focalors::elgamal_verify1(m, c1, c2, p, a, y, 10);
    cout << "flag=" << flag << endl;
}
#endif