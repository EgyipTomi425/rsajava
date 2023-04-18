package org.example;

public class Main {
    public static void main(String[] args) {
        RSA rsa = new RSA();

        RSA.KulcsPar kulcsPar = RSA.rsaKulcsgeneralas(8);
        System.out.println(kulcsPar);

        System.out.println("");
        RSA.KulcsPar kulcsPar2 = RSA.rsaKulcsgeneralas(32);
        System.out.println(kulcsPar2);

        System.out.println("");
        RSA.KulcsPar kulcsPar3 = RSA.rsaKulcsgeneralas(1024);
        System.out.println(kulcsPar3);

        System.out.println("\n-----------------------------------------------------------------------------------------\n");

        System.out.println("Kódolandó üzenet: almafa");
        String egy_titkos_uzenet_szall_a_kodban  = RSA.kodol("almafa", kulcsPar.publicKey);
        System.out.println("Üzenet kódolás után: " + egy_titkos_uzenet_szall_a_kodban + "\n");

        egy_titkos_uzenet_szall_a_kodban  = RSA.kodol("almafa", kulcsPar2.publicKey);
        System.out.println("Üzenet kódolás után: " + egy_titkos_uzenet_szall_a_kodban + "\n");

        egy_titkos_uzenet_szall_a_kodban  = RSA.kodol("almafa", kulcsPar3.publicKey);
        System.out.println("Üzenet kódolás után: " + egy_titkos_uzenet_szall_a_kodban);

        System.out.println("\n-----------------------------------------------------------------------------------------\n");

        String hozzad_is_eler_ha_feltorod_a_primet = RSA.visszafejt(RSA.kodol("almafa", kulcsPar.publicKey), kulcsPar.privateKey);
        System.out.println("Üzenet dekódolás után: " + hozzad_is_eler_ha_feltorod_a_primet + "\n");

        hozzad_is_eler_ha_feltorod_a_primet = RSA.visszafejt(RSA.kodol("almafa", kulcsPar2.publicKey), kulcsPar2.privateKey);
        System.out.println("Üzenet dekódolás után: " + hozzad_is_eler_ha_feltorod_a_primet + "\n");

        hozzad_is_eler_ha_feltorod_a_primet = RSA.visszafejt(RSA.kodol("almafa", kulcsPar3.publicKey), kulcsPar3.privateKey);
        System.out.println("Üzenet dekódolás után: " + hozzad_is_eler_ha_feltorod_a_primet + "\n");

        System.out.println("\n-----------------------------------------------------------------------------------------\n");

        System.out.println("Üzenet részekre bontása 8 bites RSA:");
        System.out.println("Üzenet dekódolás után: " +
                RSA.visszafejt(RSA.kodol("a", kulcsPar.publicKey), kulcsPar.privateKey) +
                RSA.visszafejt(RSA.kodol("l", kulcsPar.publicKey), kulcsPar.privateKey) +
                RSA.visszafejt(RSA.kodol("m", kulcsPar.publicKey), kulcsPar.privateKey) +
                RSA.visszafejt(RSA.kodol("a", kulcsPar.publicKey), kulcsPar.privateKey) +
                RSA.visszafejt(RSA.kodol("f", kulcsPar.publicKey), kulcsPar.privateKey) +
                RSA.visszafejt(RSA.kodol("a", kulcsPar.publicKey), kulcsPar.privateKey) + "\n");
    }
}