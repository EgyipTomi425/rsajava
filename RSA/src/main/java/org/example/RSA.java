package org.example;
import java.math.BigInteger;
import java.util.Random;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RSA
{
    private final static int PRIME_CERTAINTY = 10;
    private final static Random random = new Random();
    // "e" optimalizált bithossza
    private static final int MIN_BIT_LENGTH = 16;
    private static final int MAX_BIT_LENGTH = 32;

    public static BigInteger gyorshatvanyozas(BigInteger a, BigInteger b, BigInteger m)
    {
        BigInteger res = BigInteger.ONE;
        while (b.compareTo(BigInteger.ZERO) > 0)
        {
            if (b.and(BigInteger.ONE).equals(BigInteger.ONE))
            {
                res = res.multiply(a).mod(m);
            }
            a = a.multiply(a).mod(m);
            b = b.shiftRight(1);
        }
        return res;
    }

    public static BigInteger[] kibovitettEuklideszi(BigInteger a, BigInteger b)
    {
        BigInteger x = BigInteger.ZERO;
        BigInteger y = BigInteger.ONE;
        BigInteger lastx = BigInteger.ONE;
        BigInteger lasty = BigInteger.ZERO;
        BigInteger temp;
        while (!b.equals(BigInteger.ZERO))
        {
            BigInteger[] qr = a.divideAndRemainder(b);
            a = b;
            b = qr[1];
            temp = x;
            x = lastx.subtract(qr[0].multiply(x));
            lastx = temp;
            temp = y;
            y = lasty.subtract(qr[0].multiply(y));
            lasty = temp;
        }
        return new BigInteger[] {lastx, lasty, a};
    }

    // Miller-Rabin prímteszt.
    public static boolean millerRabinTeszt(BigInteger n)
    {
        if (n.compareTo(BigInteger.ONE) <= 0 || n.and(BigInteger.ONE).equals(BigInteger.ZERO))
        {
            return false;
        }

        BigInteger d = n.subtract(BigInteger.ONE);
        int s = 0;
        while (d.and(BigInteger.ONE).equals(BigInteger.ZERO))
        {
            d = d.shiftRight(1);
            s++;
        }

        for (int i = 0; i < PRIME_CERTAINTY; i++)
        {
            BigInteger a = new BigInteger(n.bitLength(), random);
            if (a.compareTo(BigInteger.TWO) < 0)
            {
                a = BigInteger.TWO;
            }
            if (a.compareTo(n.subtract(BigInteger.TWO)) > 0)
            {
                a = n.subtract(BigInteger.TWO);
            }

            BigInteger x = gyorshatvanyozas(a, d, n);
            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE)))
            {
                continue; // Nincs köze a Pythonhoz, ez a ciklust indítja újra.
            }

            boolean probablePrime = false;
            for (int j = 0; j < s - 1; j++)
            {
                x = x.multiply(x).mod(n);
                if (x.equals(BigInteger.ONE))
                {
                    return false;
                }
                if (x.equals(n.subtract(BigInteger.ONE)))
                {
                    probablePrime = true;
                    break;
                }
            }
            if (!probablePrime)
            {
                return false;
            }
        }
        return true;
    }

    public static class KulcsPar {
        private class PublicKey {
            public BigInteger n, e;

            @Override
            public String toString() {
                return "Nyilvános kulcs (n, e): (" + n + ", " + e + ")";
            }
        }

        private class PrivateKey {
            public BigInteger n, d;

            @Override
            public String toString() {
                return "Privát kulcs (n, d): (" + n + ", " + d + ")";
            }
        }

        public PublicKey publicKey;
        public PrivateKey privateKey;

        public KulcsPar(BigInteger n, BigInteger e, BigInteger d)
        {
            publicKey = new PublicKey();
            publicKey.n = n;
            publicKey.e = e;
            privateKey = new PrivateKey();
            privateKey.n = n;
            privateKey.d = d;
        }

        @Override
        public String toString()
        {
            return (((int)((publicKey.n.bitLength() + 1)/2))*2) + " bites random kulcspár:\n" + publicKey + "\n" + privateKey;
        }
    }

    public static KulcsPar rsaKulcsgeneralas(int keyLength)
    {
        BigInteger p, q, n, phi, e, d;

        do
        {
            p = BigInteger.probablePrime(keyLength/2, random);
        } while(!millerRabinTeszt(p));
        do
        {
            q = BigInteger.probablePrime(keyLength/2, random);
        } while(!millerRabinTeszt(q));

        n = p.multiply(q);
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        do
        {
            e = new BigInteger(random.nextInt(MAX_BIT_LENGTH - MIN_BIT_LENGTH + 1) + MIN_BIT_LENGTH, random);
        } while(e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE)); // e < phi(n) és relatív prím phi(n)-vel

        d = kibovitettEuklideszi(e, phi)[0].mod(phi); // a legelső érték lesz a megfelelő d

        return new KulcsPar(n, e, d);
    }

    public static String kodol(String message, KulcsPar.PublicKey publicKey)
    {
        BigInteger n = publicKey.n;
        BigInteger e = publicKey.e;
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        BigInteger messageInt = new BigInteger(1, messageBytes);
        BigInteger cipherInt = gyorshatvanyozas(messageInt, e, n);
        byte[] cipherBytes = cipherInt.toByteArray();
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    public static String visszafejt(String cipherString, KulcsPar.PrivateKey privateKey)
    {
        BigInteger n = privateKey.n;
        BigInteger d = privateKey.d;
        byte[] cipherBytes = Base64.getDecoder().decode(cipherString);
        BigInteger cipherInt = new BigInteger(1, cipherBytes);
        BigInteger messageInt = gyorshatvanyozas(cipherInt, d, n);
        byte[] messageBytes = messageInt.toByteArray();
        return new String(messageBytes, StandardCharsets.UTF_8);
    }
}
