#include "crypt.h"
#include <gmpxx.h>
#include <string>
using std::string;

namespace crypt
{
void rsa_generate_key(string &e, string &d, string &n, const int &base)
{
    mpz_class p, q, phi, e_mpz, d_mpz, n_mpz;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomb(p.get_mpz_t(), state, 512);
    mpz_urandomb(q.get_mpz_t(), state, 512);
    mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
    mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
    n_mpz = p * q;
    phi = (p - 1) * (q - 1);
    {
        mpz_class phi_2;
        phi_2 = phi - 2;
        mpz_class temp;
        do
        {
            mpz_urandomm(e_mpz.get_mpz_t(), state, phi_2.get_mpz_t());
            e_mpz += 2;
            mpz_gcd(temp.get_mpz_t(), e_mpz.get_mpz_t(), phi.get_mpz_t());
        } while (temp != 1);
    }
    mpz_invert(d_mpz.get_mpz_t(), e_mpz.get_mpz_t(), phi.get_mpz_t());
    e = e_mpz.get_str(base);
    d = d_mpz.get_str(base);
    n = n_mpz.get_str(base);
    gmp_randclear(state);
}
#ifdef DEBUG
void rsa_generate_key(string &d, string &n, const int &base, const string &p_str, const string &q_str,
                      const string &e_str)
{
    mpz_class p(p_str, base), q(q_str, base), phi, e_mpz(e_str, base), d_mpz, n_mpz;
    n_mpz = p * q;
    phi = (p - 1) * (q - 1);
    mpz_invert(d_mpz.get_mpz_t(), e_mpz.get_mpz_t(), phi.get_mpz_t());
    d = d_mpz.get_str(base);
    n = n_mpz.get_str(base);
}
#endif
string rsa_encrypt(const string &m, const string &e, const string &n, const int &base)
{
    if (m.empty())
        return m;
    mpz_class m_mpz(m, base);
    mpz_class e_mpz(e, base);
    mpz_class n_mpz(n, base);
    mpz_class sum;
    if (m_mpz >= n_mpz)
        throw std::invalid_argument("m must be less than n");
    mpz_powm_sec(sum.get_mpz_t(), m_mpz.get_mpz_t(), e_mpz.get_mpz_t(), n_mpz.get_mpz_t());
    return sum.get_str(base);
}
string rsa_decrypt(const string &c, const string &d, const string &n, const int &base)
{
    if (c.empty())
        return c;
    mpz_class c_mpz(c, base), d_mpz(d, base), n_mpz(n, base);
    if (c_mpz >= n_mpz)
        throw std::invalid_argument("c must be less than n");
    mpz_class sum;
    mpz_powm_sec(sum.get_mpz_t(), c_mpz.get_mpz_t(), d_mpz.get_mpz_t(), n_mpz.get_mpz_t());
    return sum.get_str(base);
}
} // namespace crypt

#ifdef DEBUG
#include <iostream>
using std::cout;
using std::endl;

int main()
{
    string m = "88", e = "7", d, n;
    string p = "17", q = "11";
    string c;

    crypt::rsa_generate_key(d, n, 10, p, q, e);
    cout << "d=" << d << endl;
    cout << "n=" << n << endl;

    c = crypt::rsa_decrypt(m, e, n, 10);
    cout << "c=" << c << endl;

    string decrypted = crypt::rsa_encrypt(c, d, n, 10);
    cout << "flag=" << (decrypted == m) << endl;

    return 0;
}
#endif