#!/usr/bin/perl

# gencertbuf.pl
# version 1.1
# Updated 07/01/2014
#
# Copyright (C) 2006-2015 wolfSSL Inc.
#

use strict;
use warnings;

# ---- SCRIPT SETTINGS -------------------------------------------------------

# output C header file to write cert/key buffers to
my $outputFile = "./wolfssl/mycerts.h";

# ecc keys and certs to be converted
# Used with HAVE_ECC && USE_CERT_BUFFERS_256

my @fileList_ecc = (
        );


# ed25519 keys and certs
# Used with HAVE_ED25519 define.
my @fileList_ed = (
        );

# x25519 keys and certs
# Used with USE_CERT_BUFFERS_25519 define.
my @fileList_x = (
        );


# 1024-bit certs/keys to be converted
# Used with USE_CERT_BUFFERS_1024 define.

my @fileList_1024 = (
        );

# 2048-bit certs/keys to be converted
# Used with USE_CERT_BUFFERS_2048 define.
my @fileList_2048 = (
        [ "./certs/ca-rsa.crt",         "my_cert_rsa" ],
        );

# 3072-bit certs/keys to be converted
# Used with USE_CERT_BUFFERS_3072 define.
my @fileList_3072 = (
        );

# 4096-bit certs/keys to be converted
# Used with USE_CERT_BUFFERS_4096 define.
my @fileList_4096 = (
        );

#Falcon Post-Quantum Keys
#Used with HAVE_PQC
my @fileList_falcon = (
        );

#Dilithium Post-Quantum Keys
#Used with HAVE_PQC
my @fileList_dilithium = (
        );

#Sphincs+ Post-Quantum Keys
#Used with HAVE_PQC
my @fileList_sphincs = (
        );


# ----------------------------------------------------------------------------

my $num_ecc = @fileList_ecc;
my $num_ed = @fileList_ed;
my $num_x = @fileList_x;
my $num_1024 = @fileList_1024;
my $num_2048 = @fileList_2048;
my $num_3072 = @fileList_3072;
my $num_4096 = @fileList_4096;
my $num_falcon = @fileList_falcon;
my $num_dilithium = @fileList_dilithium;
my $num_sphincs = @fileList_sphincs;

# open our output file, "+>" creates and/or truncates
open OUT_FILE, "+>", $outputFile  or die $!;

print OUT_FILE "/* certs_test.h */\n";
print OUT_FILE "/* This file was generated using: ./gencertbuf.pl */\n\n";

# convert and print 1024-bit cert/keys
print OUT_FILE "#ifdef USE_CERT_BUFFERS_1024\n\n";
for (my $i = 0; $i < $num_1024; $i++) {

    my $fname = $fileList_1024[$i][0];
    my $sname = $fileList_1024[$i][1];

    print OUT_FILE "/* $fname, 1024-bit */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}
print OUT_FILE "#endif /* USE_CERT_BUFFERS_1024 */\n\n";


# convert and print 2048-bit certs/keys
print OUT_FILE "#ifdef USE_CERT_BUFFERS_2048\n\n";
for (my $i = 0; $i < $num_2048; $i++) {

    my $fname = $fileList_2048[$i][0];
    my $sname = $fileList_2048[$i][1];

    print OUT_FILE "/* $fname, 2048-bit */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}


print OUT_FILE "#endif /* USE_CERT_BUFFERS_2048 */\n\n";


# convert and print 3072-bit certs/keys
print OUT_FILE "#ifdef USE_CERT_BUFFERS_3072\n\n";
for (my $i = 0; $i < $num_3072; $i++) {

    my $fname = $fileList_3072[$i][0];
    my $sname = $fileList_3072[$i][1];

    print OUT_FILE "/* $fname, 3072-bit */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}

print OUT_FILE "#endif /* USE_CERT_BUFFERS_3072 */\n\n";


# convert and print 4096-bit certs/keys
print OUT_FILE "#ifdef USE_CERT_BUFFERS_4096\n\n";
for (my $i = 0; $i < $num_4096; $i++) {

    my $fname = $fileList_4096[$i][0];
    my $sname = $fileList_4096[$i][1];

    print OUT_FILE "/* $fname, 4096-bit */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}

print OUT_FILE "#endif /* USE_CERT_BUFFERS_4096 */\n\n";

# convert and print falcon keys
print OUT_FILE "#if defined(HAVE_PQC) && defined(HAVE_FALCON)\n\n";
for (my $i = 0; $i < $num_falcon; $i++) {

    my $fname = $fileList_falcon[$i][0];
    my $sname = $fileList_falcon[$i][1];

    print OUT_FILE "/* $fname */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}

print OUT_FILE "#endif /* HAVE_PQC && HAVE_FALCON */\n\n";

# convert and print dilithium keys
print OUT_FILE "#if defined (HAVE_PQC) && defined(HAVE_DILITHIUM)\n\n";
for (my $i = 0; $i < $num_dilithium; $i++) {

    my $fname = $fileList_dilithium[$i][0];
    my $sname = $fileList_dilithium[$i][1];

    print OUT_FILE "/* $fname */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}

print OUT_FILE "#endif /* HAVE_PQC && HAVE_DILITHIUM */\n\n";

# convert and print sphincs keys
print OUT_FILE "#if defined(HAVE_PQC) && defined(HAVE_SPHINCS)\n\n";
for (my $i = 0; $i < $num_sphincs; $i++) {

    my $fname = $fileList_sphincs[$i][0];
    my $sname = $fileList_sphincs[$i][1];

    print OUT_FILE "/* $fname */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}

print OUT_FILE "#endif /* HAVE_PQC && HAVE_SPHINCS */\n\n";

# convert and print 256-bit cert/keys
print OUT_FILE "#if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)\n\n";
for (my $i = 0; $i < $num_ecc; $i++) {

    my $fname = $fileList_ecc[$i][0];
    my $sname = $fileList_ecc[$i][1];

    print OUT_FILE "/* $fname, ECC */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}
print OUT_FILE "#endif /* HAVE_ECC && USE_CERT_BUFFERS_256 */\n\n";



# convert and print ed25519 cert/keys
print OUT_FILE "#if defined(HAVE_ED25519)\n\n";
for (my $i = 0; $i < $num_ed; $i++) {

    my $fname = $fileList_ed[$i][0];
    my $sname = $fileList_ed[$i][1];

    print OUT_FILE "/* $fname, ED25519 */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}
print OUT_FILE "#endif /* HAVE_ED25519 */\n\n";


# convert and print CURVE25519 cert/keys
print OUT_FILE "#if defined(USE_CERT_BUFFERS_25519)\n\n";
for (my $i = 0; $i < $num_x; $i++) {

    my $fname = $fileList_x[$i][0];
    my $sname = $fileList_x[$i][1];

    print OUT_FILE "/* $fname, CURVE25519 */\n";
    print OUT_FILE "static const unsigned char $sname\[] =\n";
    print OUT_FILE "{\n";
    file_to_hex($fname);
    print OUT_FILE "};\n";
    print OUT_FILE "static const int sizeof_$sname = sizeof($sname);\n\n";
}
print OUT_FILE "#endif /* USE_CERT_BUFFERS_25519 */\n\n";

# close certs_test.h file
close OUT_FILE or die $!;

# print file as hex, comma-separated, as needed by C buffer
sub file_to_hex {
    my $fileName = $_[0];

    open my $fp, "<", $fileName or die $!;
    binmode($fp);

    my $fileLen = -s $fileName;
    my $byte;

    for (my $i = 0, my $j = 1; $i < $fileLen; $i++, $j++)
    {
        if ($j == 1) {
            print OUT_FILE "        ";
        }
        if ($j != 1) {
            print OUT_FILE " ";
        }
        read($fp, $byte, 1) or die "Error reading $fileName";
        my $output = sprintf("0x%02X", ord($byte));
        print OUT_FILE $output;

        if ($i != ($fileLen - 1)) {
            print OUT_FILE ",";
        }

        if ($j == 10) {
            $j = 0;
            print OUT_FILE "\n";
        }
    }

    print OUT_FILE "\n";

    close($fp);
}
