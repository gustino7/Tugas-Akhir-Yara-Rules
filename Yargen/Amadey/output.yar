/*
The provided rule is a YARA rule, encompassing a wide range of suspicious strings. Kindly review the list and pinpoint the twenty strings that are most distinctive or appear most suited for a YARA rule focused on malware detection. Arrange them in descending order based on their level of suspicion. Then, swap out the current list of strings in the YARA rule with your chosen set and supply the revised rule.
---
/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65 {
   meta:
      description = "Amadey_MALW - file b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65"
   strings:
      $s1 = "xmscoree.dll" fullword wide /* score: '23.00'*/
      $s2 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" fullword ascii /* score: '22.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "@api-ms-win-core-synch-l1-2-0.dll" fullword wide /* score: '20.00'*/
      $s5 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s6 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s7 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s8 = "MV1INv7CMdW6QRejeh9w67XVOH8pdiJo6YFeITOz5fWnaASleiNm6738LpPu" fullword ascii /* score: '7.00'*/
      $s9 = "BiNwHG==" fullword ascii /* score: '7.00'*/
      $s10 = "BiNw3NJ " fullword ascii /* score: '7.00'*/
      $s11 = "MV1INv7CMdW6QRejeh9w67XVOH8pdiJo6YEiLbKdIWWr hOufAZi7sLk34Y=" fullword ascii /* score: '7.00'*/
      $s12 = "MV1INv7CMdW6QRejeh9w67XVOH8pdiJo6YFeITOz5fWnaASleiNm6738IZbwdC1rRSBeNNGm5bCM8BOsdxBD67vfQZDz" fullword ascii /* score: '7.00'*/
      $s13 = "MV1INv7CMdW6QRejeh9w67XVOH8pdiJo6YFeITOz5fWnaASleiNm6738IZbwdC1rRSBeMSam4zx Oh2s1BVv7B==" fullword ascii /* score: '7.00'*/
      $s14 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s15 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s16 = "22e5bb8dbfc404311dfb1aab6222c569" ascii /* score: '6.00'*/
      $s17 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s18 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s19 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.10'*/ /* Goodware String - occured 903 times */
      $s20 = "AdsoB9uzRP5 " fullword ascii /* score: '4.00'*/
      $s21 = "LRxr47==" fullword ascii /* score: '4.00'*/
      $s22 = "WWWSHSh" fullword ascii /* score: '4.00'*/
      $s23 = "JQFHNq==" fullword ascii /* score: '4.00'*/
      $s24 = "BiFmHG==" fullword ascii /* score: '4.00'*/
      $s25 = "JBNoQNOt6yOeaCKpdhdwFqjNQZHvdDNT3R1w" fullword ascii /* score: '4.00'*/
      $s26 = "GfQkAs2G" fullword ascii /* score: '4.00'*/
      $s27 = "IQRDMRJhMV faC7hehU=" fullword ascii /* score: '4.00'*/
      $s28 = "EeszF7==" fullword ascii /* score: '4.00'*/
      $s29 = "AdsxJ7==" fullword ascii /* score: '4.00'*/
      $s30 = "KXxB5wOz5VuYFzqh0b==" fullword ascii /* score: '4.00'*/
      $s31 = "MCBxRxOk6x6a9RN=" fullword ascii /* score: '4.00'*/
      $s32 = "BdQiJNaq6vJ=" fullword ascii /* score: '4.00'*/
      $s33 = "4hB4RMOsDfWXWL==" fullword ascii /* score: '4.00'*/
      $s34 = "RSDSgMr|" fullword ascii /* score: '4.00'*/
      $s35 = "HYFl5 Ty" fullword ascii /* score: '4.00'*/
      $s36 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s37 = "EywAEpJ2FcdXLL==" fullword ascii /* score: '4.00'*/
      $s38 = "MWdVNuOOPxOo9iKydXxQT2OrDFzcWYNr6hdlRNGdIfGs8RGEcSNt6LD0OHTp1CNo" fullword ascii /* score: '4.00'*/
      $s39 = "Dud4OcCv5r i9hKlgx5t5My=" fullword ascii /* score: '4.00'*/
      $s40 = "QRBlRwOnRVii8hmsdR5s7MDt45L1fj6X7SgyEJBAFwVVKu 5NQ8=" fullword ascii /* score: '4.00'*/
      $s41 = "DhhyRm==" fullword ascii /* score: '4.00'*/
      $s42 = "JXN2Lcy13Q0eRYezfBVqM13h3y==" fullword ascii /* score: '4.00'*/
      $s43 = "DVFARMy1RLBoRVFgVPlLP0PAzE3NVusqAx1WL9t=" fullword ascii /* score: '4.00'*/
      $s44 = "AiJj5Sms3PylFx2mKx9m6Xyd" fullword ascii /* score: '4.00'*/
      $s45 = "BhJvHG==" fullword ascii /* score: '4.00'*/
      $s46 = "AdsoB9u13P2e9YO0KyEdDnWbQIPsKw==" fullword ascii /* score: '4.00'*/
      $s47 = "DSNw3MGwRzVm" fullword ascii /* score: '4.00'*/
      $s48 = "JBNoQNOt6yOeaCKpdhdwFqfNQZHvdDNT3R1w" fullword ascii /* score: '4.00'*/
      $s49 = "vLgvDITuDL1=" fullword ascii /* score: '4.00'*/
      $s50 = " delete[]" fullword ascii /* score: '4.00'*/
      $s51 = "7/7Q7s7" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s52 = "DRN6RMG26zmo9iuvdBlg9XztQYVvfCNs3R6wRMJhDN0i9BNgKb==" fullword ascii /* score: '4.00'*/
      $s53 = "5X n4wpAEb6d9Bp=" fullword ascii /* score: '4.00'*/
      $s54 = "JB1l6w2zAyeeVb==" fullword ascii /* score: '4.00'*/
      $s55 = "5iNwRwqtEsJnWSal" fullword ascii /* score: '4.00'*/
      $s56 = "IX1w6wOv6v2NbSulQdBe7Mzn2YHhfCdo4d16DN746r2f9YCtNSVv6LTpP43k1SI=" fullword ascii /* score: '4.00'*/
      $s57 = "Ax1GRMqm6zV IWKOKxI=" fullword ascii /* score: '4.00'*/
      $s58 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s59 = "MCBxRTCi4NSaaByc" fullword ascii /* score: '4.00'*/
      $s60 = "vLhF4SY1RP6TIPKpeYBs77jV2Y3uQetf4YBvDMKi6zF0FBYhdRU6CrPc5IyiQutf3Rpn4cyuRM1b" fullword ascii /* score: '4.00'*/
      $s61 = "1=1C1_1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s62 = "IYNA5cOv6xKU8Rqk" fullword ascii /* score: '4.00'*/
      $s63 = "EuQyNw21QPyMWRG1ehlX9V==" fullword ascii /* score: '4.00'*/
      $s64 = "AdsxMstj" fullword ascii /* score: '4.00'*/
      $s65 = "IX1v5xO1RQKHVRUl" fullword ascii /* score: '4.00'*/
      $s66 = "BdRH7we1" fullword ascii /* score: '4.00'*/
      $s67 = "WPWWWS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s68 = "PysyEtt=" fullword ascii /* score: '4.00'*/
      $s69 = "AxQoAq==" fullword ascii /* score: '4.00'*/
      $s70 = "EesAE7==" fullword ascii /* score: '4.00'*/
      $s71 = "MWdVNuOOPxOU iCldiRA673V4o3sWYNTPzFx4dKz4Vy6SRYpfBVhPrjfQY3cSW1HNABRLvqXKNSyQWp=" fullword ascii /* score: '4.00'*/
      $s72 = "MBp3RSev5r9=" fullword ascii /* score: '4.00'*/
      $s73 = "FeAwE t1DcRqIeB0Ob==" fullword ascii /* score: '4.00'*/
      $s74 = "BhxAHG==" fullword ascii /* score: '4.00'*/
      $s75 = "AbSMIS2v6zWnaxUUgSBiInzc4JvscSFa6Bdx492wQWSeaxUzfCJiS1YItiUK" fullword ascii /* score: '4.00'*/
      $s76 = "NhdmRM2KJt==" fullword ascii /* score: '4.00'*/
      $s77 = "MYJj5dK25t==" fullword ascii /* score: '4.00'*/
      $s78 = "BhBrHG==" fullword ascii /* score: '4.00'*/
      $s79 = "Ihd2RwOnRP6dWSB=" fullword ascii /* score: '4.00'*/
      $s80 = "QYBnRsYl4zy1VXqpex5h6Lv3" fullword ascii /* score: '4.00'*/
      $s81 = "DNSPu7==" fullword ascii /* score: '4.00'*/
      $s82 = "BitlHG==" fullword ascii /* score: '4.00'*/
      $s83 = "GgAkAs2G" fullword ascii /* score: '4.00'*/
      $s84 = "5iNwRwqtEsJ " fullword ascii /* score: '4.00'*/
      $s85 = "3CJ25thwDp==" fullword ascii /* score: '4.00'*/
      $s86 = "MCBxRTCi4QN=" fullword ascii /* score: '4.00'*/
      $s87 = "RRFq4ou08xOuNVqTKxI=" fullword ascii /* score: '4.00'*/
      $s88 = "EPPhP?C" fullword ascii /* score: '4.00'*/
      $s89 = "Pzxy5q==" fullword ascii /* score: '4.00'*/
      $s90 = "BQNVJLCRMd zPPqFLL==" fullword ascii /* score: '4.00'*/
      $s91 = "FBA7QJxxFfVWKb==" fullword ascii /* score: '4.00'*/
      $s92 = "MVFKNuyUKUN=" fullword ascii /* score: '4.00'*/
      $s93 = "BiRBHG==" fullword ascii /* score: '4.00'*/
      $s94 = "= =$=6=H=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s95 = "IX1w6wOv6v2NbSulQdBq81vV2ZvhejIoRh1A4IUlQQSaLtuidYVrTLDt6VUtNOSm" fullword ascii /* score: '4.00'*/
      $s96 = "IVxFLvFhA ==" fullword ascii /* score: '4.00'*/
      $s97 = "NXdwJwOnRP6dWSB=" fullword ascii /* score: '4.00'*/
      $s98 = "MWdVNuOOPxOU iCldiRA673V4o3sWYNTPzFx4dKz4Vy6NX2teCVXT2HJPYVlZAFo4St36wOzLfGmWL==" fullword ascii /* score: '4.00'*/
      $s99 = "QXTmAs2EAyKGOzeSKx9wF8Cb" fullword ascii /* score: '4.00'*/
      $s100 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s101 = "VVVVhl?C" fullword ascii /* score: '4.00'*/
      $s102 = "EeszGG==" fullword ascii /* score: '4.00'*/
      $s103 = "3XNA4cOtEsJnWBqs" fullword ascii /* score: '4.00'*/
      $s104 = "9 9$9(9,9094989<9@9D9H9T9X9\\9`9d9h9l9p9t9x9|9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s105 = "DNSvDITu" fullword ascii /* score: '4.00'*/
      $s106 = "1$2W2}2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s107 = "ISRr5cx=" fullword ascii /* score: '4.00'*/
      $s108 = "8,808L8P8X8`8h8l8t8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s109 = "Bapi-ms-win-core-fibers-l1-1-1" fullword wide /* score: '4.00'*/
      $s110 = "Bapi-ms-win-core-datetime-l1-1-1" fullword wide /* score: '4.00'*/
      $s111 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s112 = "363c314b34b4864ac6a85f962c5ac734" ascii /* score: '3.00'*/
      $s113 = "c1ec479e5342a25940592acf24703eb2" ascii /* score: '3.00'*/
      $s114 = " delete" fullword ascii /* score: '3.00'*/
      $s115 = "7(7,7074787<7@7D7" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s116 = ">2>C>q>" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s117 = "MV1INv7CMdW6QRejeh9w67XVOH8pdiJo6YFeITOz5fWnaASleiNm6738LpPuVYXcRL==" fullword ascii /* score: '3.00'*/
      $s118 = "Cja-JP" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s119 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s120 = "l1t1|1" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s121 = "616Y6m6" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s122 = "676A6K6b6l6" fullword ascii /* score: '1.00'*/
      $s123 = "D8(Ht'" fullword ascii /* score: '1.00'*/
      $s124 = ";7;A;K;b;l;" fullword ascii /* score: '1.00'*/
      $s125 = "536\\6f6" fullword ascii /* score: '1.00'*/
      $s126 = ";+<0<4<8<<<" fullword ascii /* score: '1.00'*/
      $s127 = "<!<+<B<L<w<" fullword ascii /* score: '1.00'*/
      $s128 = "<K=R=Y=`=m=" fullword ascii /* score: '1.00'*/
      $s129 = "d5h5l5p5" fullword ascii /* score: '1.00'*/
      $s130 = "V0h0-2^2d2" fullword ascii /* score: '1.00'*/
      $s131 = "4\"4,4W4a4k4" fullword ascii /* score: '1.00'*/
      $s132 = "7!7+7B7L7w7" fullword ascii /* score: '1.00'*/
      $s133 = "171A1K1b1l1" fullword ascii /* score: '1.00'*/
      $s134 = "<<<[<v<" fullword ascii /* score: '1.00'*/
      $s135 = ";\";,;W;a;k;" fullword ascii /* score: '1.00'*/
      $s136 = ":\":,:W:a:k:" fullword ascii /* score: '1.00'*/
      $s137 = ":*:1:D:Q:n:" fullword ascii /* score: '1.00'*/
      $s138 = "Bh1pHG==" fullword ascii /* score: '1.00'*/
      $s139 = "9\"9,9W9a9k9" fullword ascii /* score: '1.00'*/
      $s140 = "5!5+5B5L5w5" fullword ascii /* score: '1.00'*/
      $s141 = ";+<C<p<" fullword ascii /* score: '1.00'*/
      $s142 = ":9;B;O;U;" fullword ascii /* score: '1.00'*/
      $s143 = "=\"=,=W=a=k=" fullword ascii /* score: '1.00'*/
      $s144 = "l0p0x0" fullword ascii /* score: '1.00'*/
      $s145 = " new[]" fullword ascii /* score: '1.00'*/
      $s146 = ";!;+;B;L;w;" fullword ascii /* score: '1.00'*/
      $s147 = "8\"8,8W8a8k8" fullword ascii /* score: '1.00'*/
      $s148 = "8!8<8F8R8W8\\8z8" fullword ascii /* score: '1.00'*/
      $s149 = "2)3i3u3" fullword ascii /* score: '1.00'*/
      $s150 = ":\":M:S:]:g:s:" fullword ascii /* score: '1.00'*/
      $s151 = "62fadb" ascii /* score: '1.00'*/
      $s152 = "7H8^8q8{8*939;9v9" fullword ascii /* score: '1.00'*/
      $s153 = "8(9D9P9^9" fullword ascii /* score: '1.00'*/
      $s154 = ":*;5;w<" fullword ascii /* score: '1.00'*/
      $s155 = "474A4K4b4l4" fullword ascii /* score: '1.00'*/
      $s156 = "E hH?C" fullword ascii /* score: '1.00'*/
      $s157 = "?!?+?B?L?w?" fullword ascii /* score: '1.00'*/
      $s158 = "6:6:8f8" fullword ascii /* score: '1.00'*/
      $s159 = "0#0(020A0Q0a0s0x0" fullword ascii /* score: '1.00'*/
      $s160 = "7s:Y;7<^<" fullword ascii /* score: '1.00'*/
      $s161 = "0!0-060;0A0K0U0e0u0" fullword ascii /* score: '1.00'*/
      $s162 = "112=2Q2]2i2" fullword ascii /* score: '1.00'*/
      $s163 = "0%0/0<0F0V0" fullword ascii /* score: '1.00'*/
      $s164 = "3 3$383H3L3\\3l3|3" fullword ascii /* score: '1.00'*/
      $s165 = ";@;W;^;g;w;};" fullword ascii /* score: '1.00'*/
      $s166 = "=4>_>z>" fullword ascii /* score: '1.00'*/
      $s167 = "282?2D2H2L2P2" fullword ascii /* score: '1.00'*/
      $s168 = "6\"6,6W6a6k6" fullword ascii /* score: '1.00'*/
      $s169 = "00090q0" fullword ascii /* score: '1.00'*/
      $s170 = ">(>6>D>O>e>y>" fullword ascii /* score: '1.00'*/
      $s171 = ">'>,>=>C>H>S>]>d>j>t>" fullword ascii /* score: '1.00'*/
      $s172 = ":7:A:K:b:l:" fullword ascii /* score: '1.00'*/
      $s173 = "j@hp:C" fullword ascii /* score: '1.00'*/
      $s174 = "4'5`6z7" fullword ascii /* score: '1.00'*/
      $s175 = "2!2+2B2L2w2" fullword ascii /* score: '1.00'*/
      $s176 = "6%6G6p6" fullword ascii /* score: '1.00'*/
      $s177 = "=#=-=8=S=l=" fullword ascii /* score: '1.00'*/
      $s178 = "5#5U5a5~6" fullword ascii /* score: '1.00'*/
      $s179 = "9=:H:N:W:" fullword ascii /* score: '1.00'*/
      $s180 = "Ax1WM9tj" fullword ascii /* score: '1.00'*/
      $s181 = "6/6:6B6M6S6^6d6r6" fullword ascii /* score: '1.00'*/
      $s182 = ":!:+:B:L:w:" fullword ascii /* score: '1.00'*/
      $s183 = "5$6J6z6" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s184 = ">7>A>K>b>l>" fullword ascii /* score: '1.00'*/
      $s185 = "575A5K5b5l5" fullword ascii /* score: '1.00'*/
      $s186 = "<*<5<;<E<V<]<" fullword ascii /* score: '1.00'*/
      $s187 = "u kE$<" fullword ascii /* score: '1.00'*/
      $s188 = "4$5W5j5" fullword ascii /* score: '1.00'*/
      $s189 = "76708L9" fullword ascii /* score: '1.00'*/
      $s190 = ":0;<;M;X;g;l;" fullword ascii /* score: '1.00'*/
      $s191 = "1h2p4u4" fullword ascii /* score: '1.00'*/
      $s192 = "?1N1\\1`1d1h1l1p1t1x1|1" fullword ascii /* score: '1.00'*/
      $s193 = "<'<9<K>g>" fullword ascii /* score: '1.00'*/
      $s194 = "1\"1,1W1a1k1" fullword ascii /* score: '1.00'*/
      $s195 = "9!9+9B9L9w9" fullword ascii /* score: '1.00'*/
      $s196 = ">(>Q>f>x>" fullword ascii /* score: '1.00'*/
      $s197 = "2T2;3J3" fullword ascii /* score: '1.00'*/
      $s198 = "8]8D9S9" fullword ascii /* score: '1.00'*/
      $s199 = "272A2K2b2l2" fullword ascii /* score: '1.00'*/
      $s200 = "98:A:n:w:" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1 {
   meta:
      description = "Amadey_MALW - file 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s4 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "J9TNTZdp3KPodF4N QvnHdv7eJxx70JleyeyefdqN7LfdF4s9ADnRRUCEiWP" fullword ascii /* score: '9.00'*/
      $s7 = "?3?9?>?`?" fullword ascii /* score: '9.00'*/ /* hex encoded string '9' */
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s9 = ":$:,:0:8:L:T:\\:h:" fullword ascii /* score: '7.00'*/
      $s10 = "9':1:;:R:\\:" fullword ascii /* score: '7.00'*/
      $s11 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s12 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s13 = "vector too long" fullword ascii /* score: '6.00'*/
      $s14 = "list too long" fullword ascii /* score: '6.00'*/
      $s15 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s16 = "KfOxdUV4" fullword ascii /* score: '5.00'*/
      $s17 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" fullword ascii /* score: '5.00'*/
      $s18 = ".?AV?$_Func_impl_no_alloc@V?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@X$$V@std@@" fullword ascii /* score: '5.00'*/
      $s19 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s20 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s21 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s22 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s23 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s24 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s25 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s26 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s27 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s28 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s29 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s30 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s31 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
      $s32 = "WWWSHSh" fullword ascii /* score: '4.00'*/
      $s33 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s34 = " delete[]" fullword ascii /* score: '4.00'*/
      $s35 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s36 = "WPWWWS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s37 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s38 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s39 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" fullword ascii /* score: '4.00'*/
      $s40 = "VSGLYBKOH5G=" fullword ascii /* score: '4.00'*/
      $s41 = "?$?4?8?L?P?`?d?h?p?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s42 = "cy@@@?$task@E@Concurrency@@U_TaskProcHandle@details@3@@details@Concurrency@@" fullword ascii /* score: '4.00'*/
      $s43 = "bUOBej0nBDCoZJAl" fullword ascii /* score: '4.00'*/
      $s44 = "Ywyzfx==" fullword ascii /* score: '4.00'*/
      $s45 = "7 8V8e8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s46 = "728?8M8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s47 = "VqToeEZo" fullword ascii /* score: '4.00'*/
      $s48 = "MPOxdTSqOKOn" fullword ascii /* score: '4.00'*/
      $s49 = "VVKkfkWW2E==" fullword ascii /* score: '4.00'*/
      $s50 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" fullword ascii /* score: '4.00'*/
      $s51 = "VS2JYCiwJoP7TZoc8f3B5XTPZH u8qNzeVGfT00t2qPodI2e8gHr5XZ2WpRzP61n0I==" fullword ascii /* score: '4.00'*/
      $s52 = "323<3g3q3{3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s53 = "3U3c3p3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s54 = ".?AV_ExceptionPtr_normal@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s55 = ".?AV?$_Func_impl_no_alloc@V<lambda_0456396a71e3abd88ede77bdd2823d8e>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s56 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s57 = ".?AV?$_Ref_count_obj2@U_ExceptionHolder@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s58 = ".?AV?$_Func_impl_no_alloc@V<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@E$$V@std@@" fullword ascii /* score: '4.00'*/
      $s59 = "MSGB2TKVOWupU3P ONfQOQLuKE5SPCwBJu2XWfF=" fullword ascii /* score: '4.00'*/
      $s60 = "JatpMfGV00Vfb6YTDwyiCdS61IRxEE==" fullword ascii /* score: '4.00'*/
      $s61 = "RNSEXYVbJ63gdKga8fO=" fullword ascii /* score: '4.00'*/
      $s62 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s63 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s64 = "RSyGWCRbxk==" fullword ascii /* score: '4.00'*/
      $s65 = "VTeWYB0IMIHVcqMe7gLF5XZPeo5xQ6R4YwGyekWt16r7Q5bm8AP2SSDD0YXqTIJzcPu4gD0tIqznZT==" fullword ascii /* score: '4.00'*/
      $s66 = "0D0h0z0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s67 = "dUa4gDWq36YaL0P GQKiFv==" fullword ascii /* score: '4.00'*/
      $s68 = "MOO72TSW3KfpbqEo7zfl8Nvn1YXA KRDbO7x2TVbAYTjbJX D ==" fullword ascii /* score: '4.00'*/
      $s69 = "VzCy20Oc1YLbdJI6" fullword ascii /* score: '4.00'*/
      $s70 = "171G1d1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s71 = "VS2JYCiwJoP7TZoc8f3B5XTPZH u8qNzeVGfT00t2qPodI2e8gHr5XZ2WpRz" fullword ascii /* score: '4.00'*/
      $s72 = "Vyyx2DJbJ6Pdd0Mi9Ae=" fullword ascii /* score: '4.00'*/
      $s73 = "JatpMfGtO0Ya" fullword ascii /* score: '4.00'*/
      $s74 = "JfKkfZym00rmIFbfDv3r5Nu8" fullword ascii /* score: '4.00'*/
      $s75 = "SyOp1U0n3JHfdKUi7f8BEgfH1ZJA8LR4bO2x" fullword ascii /* score: '4.00'*/
      $s76 = "KaRjUUmk3GC=" fullword ascii /* score: '4.00'*/
      $s77 = "SNGIYx==" fullword ascii /* score: '4.00'*/
      $s78 = "OuXAPt==" fullword ascii /* score: '4.00'*/
      $s79 = ".?AV?$_Func_impl_no_alloc@V<lambda_9de88c4009318ef1202283857f94e673>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s80 = "RU2xgD0p3GVOe0EeJbvv7RrPcZxm9rMz0e2BeP6fN1LbOBEb7WPwSBzngVWyHWWx" fullword ascii /* score: '4.00'*/
      $s81 = ".?AV?$_Ref_count_obj2@U?$_Task_impl@E@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s82 = "EIiGeZ VO0ZULXUi8Wvx6XfPcY5zKmxqcVCwOTWc3Ky1IJ8a7POaBhL7fIAnKCxqbOqoejKoOXUc" fullword ascii /* score: '4.00'*/
      $s83 = "KNOWUSOLJo3ASXAyEJ==" fullword ascii /* score: '4.00'*/
      $s84 = "6$686@6H6T6t6|6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s85 = "OKX3Pf9XCWYrMmX=" fullword ascii /* score: '4.00'*/
      $s86 = "YvtzPAF=" fullword ascii /* score: '4.00'*/
      $s87 = "VTeWYB0IMIHpbqUr7VrVSSKlOFBhQ6RCeeem2US8FqztaZQx6QHy5BzUZHVuVKRz" fullword ascii /* score: '4.00'*/
      $s88 = "dUaoeDBuBmZebJz=" fullword ascii /* score: '4.00'*/
      $s89 = "FYY;w(|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s90 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s91 = "MKTwOP5o" fullword ascii /* score: '4.00'*/
      $s92 = "EIhwOP5oAWU=" fullword ascii /* score: '4.00'*/
      $s93 = "VTeWYB0IMIHVcqMe7gLF5XZPeo5xQ6R4YwGyekWt16r7VZ8i9zPmOhf 1Y5hM45SWxCSWCCRHYLzT4z=" fullword ascii /* score: '4.00'*/
      $s94 = "SUO3WjKV01TfU6os9zPvLRZbdy==" fullword ascii /* score: '4.00'*/
      $s95 = "RVOBfj0p3IDVaZAd" fullword ascii /* score: '4.00'*/
      $s96 = "UOysed==" fullword ascii /* score: '4.00'*/
      $s97 = "VzCy2E0e3IZbbZX=" fullword ascii /* score: '4.00'*/
      $s98 = "VS2JYCiwJoP7TZoc8f3B5XTPZH u8qNzeVGfT00t2qPodI2e8gHr5XZ2TZdB8K5C0PCfXZmg1KqaRpblUzPA6r==" fullword ascii /* score: '4.00'*/
      $s99 = "NbtARN==" fullword ascii /* score: '4.00'*/
      $s100 = "NyKoRQGhNDPdNz==" fullword ascii /* score: '4.00'*/
      $s101 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s102 = "RPSsfjJ=" fullword ascii /* score: '4.00'*/
      $s103 = "rrency@@" fullword ascii /* score: '4.00'*/
      $s104 = "VzCy20Oc11G=" fullword ascii /* score: '4.00'*/
      $s105 = ":4:H:S:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s106 = "VS2JYCiwJoP7TZoc8f3B5XTPZH u8qNzeVFjWiW8F7PscpYn9yTn6iHed40=" fullword ascii /* score: '4.00'*/
      $s107 = "Ju2H2TCg3KOaL4UHDvC=" fullword ascii /* score: '4.00'*/
      $s108 = "MUl8PjCuFXHecJLo6PZmSSajeIdB" fullword ascii /* score: '4.00'*/
      $s109 = "KKUvgN==" fullword ascii /* score: '4.00'*/
      $s110 = "PdBlLzdA" fullword ascii /* score: '4.00'*/
      $s111 = "ZVCo2z f1Kr2Y5Ai8vZm5BrX" fullword ascii /* score: '4.00'*/
      $s112 = "4$444@4`4h4p4x4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s113 = "Ween2TdEGE==" fullword ascii /* score: '4.00'*/
      $s114 = "QVGmfg5s" fullword ascii /* score: '4.00'*/
      $s115 = ".?AV?$_Task_async_state@X@std@@" fullword ascii /* score: '4.00'*/
      $s116 = "JuRpLx==" fullword ascii /* score: '4.00'*/
      $s117 = "TUyCfD0t26nZIHAaT ==" fullword ascii /* score: '4.00'*/
      $s118 = "MKOvgN==" fullword ascii /* score: '4.00'*/
      $s119 = "Sy2mgDdtxJ8fYj==" fullword ascii /* score: '4.00'*/
      $s120 = "Meiz2t==" fullword ascii /* score: '4.00'*/
      $s121 = "JatyUd==" fullword ascii /* score: '4.00'*/
      $s122 = "dVJbft==" fullword ascii /* score: '4.00'*/
      $s123 = "NbtAQd==" fullword ascii /* score: '4.00'*/
      $s124 = "?1?<?J?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s125 = "MTuvgTik1rGp" fullword ascii /* score: '4.00'*/
      $s126 = "SyOp1U0n3JHfdKUi7f8BEgbH1ZJA8LR4bO2x" fullword ascii /* score: '4.00'*/
      $s127 = "1 1$14181H1L1\\1`1d1l1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s128 = "0OGrevGU5IHvQ3AMDvC=" fullword ascii /* score: '4.00'*/
      $s129 = "ZOCm2D0hO6bjapwl7PZx6Czne5N6 r 8fPhzPQNuCHOWNCjYGO2=" fullword ascii /* score: '4.00'*/
      $s130 = "bzK3fAtqAA==" fullword ascii /* score: '4.00'*/
      $s131 = "MKTQFd==" fullword ascii /* score: '4.00'*/
      $s132 = "2\\3k3x3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s133 = ".?AV?$_Func_impl_no_alloc@V<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s134 = "Wj4XPV" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s135 = "NbtBPd==" fullword ascii /* score: '4.00'*/
      $s136 = "NvxBPwVWCn7YOT==" fullword ascii /* score: '4.00'*/
      $s137 = "WUexUD0hO0ZeZ0L=" fullword ascii /* score: '4.00'*/
      $s138 = "dfOx2DCnBDCoZ0ke" fullword ascii /* score: '4.00'*/
      $s139 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s140 = "NrRzYDdVN0rNZZQU8ff28L==" fullword ascii /* score: '4.00'*/
      $s141 = "WPKChUSeAqPYZT==" fullword ascii /* score: '4.00'*/
      $s142 = "KaSIhDqV" fullword ascii /* score: '4.00'*/
      $s143 = "Vy262UOu0KPmbF8e zO=" fullword ascii /* score: '4.00'*/
      $s144 = "JatyXzFd" fullword ascii /* score: '4.00'*/
      $s145 = "ZUUnLzdyxJDHRHoLDv3BEYy6" fullword ascii /* score: '4.00'*/
      $s146 = "YYF;w,|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s147 = "VS2JYCiwJoP7TZoc8f3B5XTPZH u8qNzeVGfT00t2qPodI2e8gHr5XZ2TZdB8K5C0PCfYUSg2mvNaJYl7vvI5Xr 1ZFE" fullword ascii /* score: '4.00'*/
      $s148 = ".?AV?$_Func_impl_no_alloc@V<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s149 = ";R<V<Z<^<b<f<j<n<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s150 = "Eapi-ms-win-core-fibers-l1-1-1" fullword wide /* score: '4.00'*/
      $s151 = "Eapi-ms-win-core-datetime-l1-1-1" fullword wide /* score: '4.00'*/
      $s152 = "system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.42'*/ /* Goodware String - occured 1577 times */
      $s153 = " delete" fullword ascii /* score: '3.00'*/
      $s154 = ";1#INF" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s155 = "07c6bc37dc50874878dcb010336ed906" ascii /* score: '3.00'*/
      $s156 = ">(>.>4>" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s157 = "9de88c4009318ef1202283857f94e673" ascii /* score: '3.00'*/
      $s158 = "b34dd8f60e55add4645c4650cc7f7e7e" ascii /* score: '3.00'*/
      $s159 = ".?AV?$_Func_base@E$$V@std@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s160 = ".?AV?$_CancellationTokenCallback@V<lambda_3b8ab8d2629adf61a42ee3fe177a046b>@@@details@Concurrency@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s161 = "242W2z2" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s162 = "3b8ab8d2629adf61a42ee3fe177a046b" ascii /* score: '3.00'*/
      $s163 = "9#:L:u:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s164 = "7c33b2c4310ad8c6be497d7a2a561bb8" ascii /* score: '3.00'*/
      $s165 = "V0g0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s166 = "50585@5" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s167 = "</<T<t<" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s168 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s169 = "eb87dfd73f857f44e1a351ea42ce2b34" ascii /* score: '3.00'*/
      $s170 = "F0K0]0{0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s171 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s172 = "8p9V:h:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s173 = "=1=S=u=" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s174 = "bba5a2d8dde515d038c8c02fc2a9bfe5" ascii /* score: '3.00'*/
      $s175 = "0456396a71e3abd88ede77bdd2823d8e" ascii /* score: '3.00'*/
      $s176 = "?0?K?c?" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s177 = "5e5ab22ea98f4361dbf159481d01f54d" ascii /* score: '3.00'*/
      $s178 = ".?AV<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s179 = "7:8G8[8" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s180 = "Eja-JP" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s181 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s182 = "3 4(40484@4H4P4X4`4h4p4x4" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s183 = "6F6X6u6" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s184 = ";-;H;s;" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s185 = "D8(Ht'" fullword ascii /* score: '1.00'*/
      $s186 = " new[]" fullword ascii /* score: '1.00'*/
      $s187 = "u kE$<" fullword ascii /* score: '1.00'*/
      $s188 = ":u\"f9z" fullword ascii /* score: '1.00'*/
      $s189 = "UTF-16LEUNICODE" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s190 = "CM @PRj" fullword ascii /* score: '1.00'*/
      $s191 = "<=upG8" fullword ascii /* score: '1.00'*/
      $s192 = "zSSSSj" fullword ascii /* score: '1.00'*/
      $s193 = "<at.<rt!<wt" fullword ascii /* score: '1.00'*/
      $s194 = "api-ms-" fullword wide /* score: '1.00'*/
      $s195 = "ext-ms-" fullword wide /* score: '1.00'*/
      $s196 = "e2J5V5w5" fullword ascii /* score: '1.00'*/
      $s197 = "=5>O>T>" fullword ascii /* score: '1.00'*/
      $s198 = "8,:Q:h:x:" fullword ascii /* score: '1.00'*/
      $s199 = "4 4(4,40484L4T4X4`4t4|4" fullword ascii /* score: '1.00'*/
      $s200 = "8'919;9G9S9a9r9" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77 {
   meta:
      description = "Amadey_MALW - file 488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s4 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s7 = "9':1:;:R:\\:" fullword ascii /* score: '7.00'*/
      $s8 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s9 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s10 = "vector too long" fullword ascii /* score: '6.00'*/
      $s11 = "list too long" fullword ascii /* score: '6.00'*/
      $s12 = "39d075ccccc6ab719903f5c886b5cc14" ascii /* score: '6.00'*/
      $s13 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s14 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" fullword ascii /* score: '5.00'*/
      $s15 = ".?AV?$_Func_impl_no_alloc@V?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@X$$V@std@@" fullword ascii /* score: '5.00'*/
      $s16 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s17 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s18 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s19 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s20 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s21 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s22 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s23 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s24 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s25 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s26 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s27 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s28 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
      $s29 = "WWWSHSh" fullword ascii /* score: '4.00'*/
      $s30 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s31 = " delete[]" fullword ascii /* score: '4.00'*/
      $s32 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s33 = "WPWWWS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s34 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s35 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s36 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" fullword ascii /* score: '4.00'*/
      $s37 = "cy@@@?$task@E@Concurrency@@U_TaskProcHandle@details@3@@details@Concurrency@@" fullword ascii /* score: '4.00'*/
      $s38 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" fullword ascii /* score: '4.00'*/
      $s39 = "323<3g3q3{3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s40 = ".?AV_ExceptionPtr_normal@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s41 = ".?AV?$_Func_impl_no_alloc@V<lambda_0456396a71e3abd88ede77bdd2823d8e>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s42 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s43 = ".?AV?$_Ref_count_obj2@U_ExceptionHolder@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s44 = ".?AV?$_Func_impl_no_alloc@V<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@E$$V@std@@" fullword ascii /* score: '4.00'*/
      $s45 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s46 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s47 = ".?AV?$_Func_impl_no_alloc@V<lambda_9de88c4009318ef1202283857f94e673>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s48 = ".?AV?$_Ref_count_obj2@U?$_Task_impl@E@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s49 = "FYY;w(|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s50 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s51 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s52 = "rrency@@" fullword ascii /* score: '4.00'*/
      $s53 = ".?AV?$_Task_async_state@X@std@@" fullword ascii /* score: '4.00'*/
      $s54 = ".?AV?$_Func_impl_no_alloc@V<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s55 = "Wj4XPV" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s56 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s57 = "YYF;w,|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s58 = ".?AV?$_Func_impl_no_alloc@V<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s59 = "Eapi-ms-win-core-fibers-l1-1-1" fullword wide /* score: '4.00'*/
      $s60 = "Eapi-ms-win-core-datetime-l1-1-1" fullword wide /* score: '4.00'*/
      $s61 = "?.?T?~?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s62 = "888?8h8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s63 = "XwOlUwTn5J m MM=" fullword ascii /* score: '4.00'*/
      $s64 = "YRqkMvTqQ1 pXNA=" fullword ascii /* score: '4.00'*/
      $s65 = "1LO UvTqQ7mu9clu617kdEBwcSUV9r3ZhMtmHIGDEIZ7Lp97F0 =" fullword ascii /* score: '4.00'*/
      $s66 = "TRdk9vTy5H6ZcNtnInD7dExqaLQb9Kaqe8dUGMb75D6r TBvF2XncDRsYRbeU0F=" fullword ascii /* score: '4.00'*/
      $s67 = "1R6aDr7HzKOSPudUCHaoM0Ae" fullword ascii /* score: '4.00'*/
      $s68 = "7L7[7z7" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s69 = "fbKkUv7x" fullword ascii /* score: '4.00'*/
      $s70 = "XQqJQtTROJSA dJA67zI0UMuMsI7P6Ktgbq UMLgHrKE9MFG52PlcDB3Xu2jUKKq" fullword ascii /* score: '4.00'*/
      $s71 = "ObumUl==" fullword ascii /* score: '4.00'*/
      $s72 = "Uv0cTMTw5KSqbxJr6rfoMihQZMQp7LKVdLdk" fullword ascii /* score: '4.00'*/
      $s73 = "XtdJQp==" fullword ascii /* score: '4.00'*/
      $s74 = "1l1p1t1x1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s75 = "dwWQ8wK CDc=" fullword ascii /* score: '4.00'*/
      $s76 = "dwWQ8smzCB==" fullword ascii /* score: '4.00'*/
      $s77 = "Wbdo9v7y" fullword ascii /* score: '4.00'*/
      $s78 = "XQqJQtTROJS6adBn6sTscZ1YcbbmP6KV0tSl7cPC37ChTMXr8LX WjhiZLb7L4YJYuOFOuv0JZWKRRo=" fullword ascii /* score: '4.00'*/
      $s79 = "1/151;1A1G1M1T1[1b1i1p1w1~1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s80 = "8,848<8@8H8\\8d8l8t8x8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s81 = "9Q9j9|9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s82 = "GFtjGHYxCX5=" fullword ascii /* score: '4.00'*/
      $s83 = "Po3mQv74P1CYXMF37rnPfN==" fullword ascii /* score: '4.00'*/
      $s84 = "Uv0cTMTw5KSqbxJr6rfoMidQZMQp7LKVdLdk" fullword ascii /* score: '4.00'*/
      $s85 = "8(8T8x8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s86 = "XvdTUMHD2L0x sXn9LW=" fullword ascii /* score: '4.00'*/
      $s87 = "YbqaUL7NIF==" fullword ascii /* score: '4.00'*/
      $s88 = "fc0kUvvwDENl" fullword ascii /* score: '4.00'*/
      $s89 = "1SObUr3o3LCcWSpr7H7 cDt6" fullword ascii /* score: '4.00'*/
      $s90 = "TRdk9vTy5H6ZcNtnInDieTtYaMEb8rFq2bdo7HZoP2WmMotk68Xj0DBweI3nGWPo" fullword ascii /* score: '4.00'*/
      $s91 = "fc0kUvvwDENzXN n" fullword ascii /* score: '4.00'*/
      $s92 = "XPdwQubFLp0hRMdl7raocZVYXugj7qGqgSS3LSTC4r0zbvRn7sPecZ1aRMkq7KYt2MO3QMLp4nGY9wNu6HDvcZtiZMMt" fullword ascii /* score: '4.00'*/
      $s93 = "162S2_2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s94 = "TbqQUvTqQ1 pXNA=" fullword ascii /* score: '4.00'*/
      $s95 = "708Z8k8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s96 = "PIlRG9C7Dn9CK 9wGYGR" fullword ascii /* score: '4.00'*/
      $s97 = "OQGi9Lbt3sRA" fullword ascii /* score: '4.00'*/
      $s98 = "9 9$94989H9L9\\9`9d9h9p9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s99 = "0sFmHsy=" fullword ascii /* score: '4.00'*/
      $s100 = "XPdwQubFLp0hRMdl7raocZVYXugj7qGqgSS3LSTC4r0zbvRn7sPecZ1aUcYoO6Ue2F==" fullword ascii /* score: '4.00'*/
      $s101 = "193STIflQYF8L7==" fullword ascii /* score: '4.00'*/
      $s102 = "7<8D8K8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s103 = "LcW88Rrv21CxGs1oCHaecPwg" fullword ascii /* score: '4.00'*/
      $s104 = "282@2P2t2|2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s105 = "2(242\\2l2x2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s106 = "WLKf76==" fullword ascii /* score: '4.00'*/
      $s107 = "TRdj8wT4Q2OTWMTn" fullword ascii /* score: '4.00'*/
      $s108 = "fRmR9vPz579lJNEiF2S6Nx==" fullword ascii /* score: '4.00'*/
      $s109 = "VRKp8vTC47y GupjSl==" fullword ascii /* score: '4.00'*/
      $s110 = "OL0UULL55LqA dtx6Ln9fPxwZL4p9KKudLikULOkCZ4u wMiCl==" fullword ascii /* score: '4.00'*/
      $s111 = "5 5(5@5P5T5h5l5|5" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s112 = "fSVZ8l==" fullword ascii /* score: '4.00'*/
      $s113 = "XQqJQtTROJS6adBn6sTscZ1YcbbmP6KV0tSl7cPC37ChOS1v7MXP0UFMYL4fSICqeMGR9vTCKrKyXG==" fullword ascii /* score: '4.00'*/
      $s114 = "L65ALR7y5L0zbsTW92DaPfxfcwEm60Ccgvql787zP8WqbsTB8MLaZTWLC63E" fullword ascii /* score: '4.00'*/
      $s115 = "XwOlUSHl32R=" fullword ascii /* score: '4.00'*/
      $s116 = "UKSvQp==" fullword ascii /* score: '4.00'*/
      $s117 = "=>>R>c>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s118 = "MK0JMKHULpdLQKpHDV==" fullword ascii /* score: '4.00'*/
      $s119 = "8,9R9z9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s120 = "OP69HPb6L2R9JSdwTLXTMkxmcp==" fullword ascii /* score: '4.00'*/
      $s121 = "TRdj7RPz" fullword ascii /* score: '4.00'*/
      $s122 = "UR0QObD4224qSTdB8LXiTT1kbl==" fullword ascii /* score: '4.00'*/
      $s123 = "GFut7R34Q1 5JKJr78DkdZhYaLboJmqheSOjGLPl5LJbGwXj61WYJjNfdvHcJCqhdLCb7bDxQY5n" fullword ascii /* score: '4.00'*/
      $s124 = "323E3\\3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s125 = ">$>8>G>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s126 = "XPdwQubFLp0hRMdl7raocZVYXugj7qGqgSS3LSTC4r0zbvRn7sPecZ1aUcYo" fullword ascii /* score: '4.00'*/
      $s127 = "Uvd 9v7CzKiqW7==" fullword ascii /* score: '4.00'*/
      $s128 = ";A;[;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s129 = "5!6R6~6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s130 = "XPdwQubFLp0hRMdl7raocZVYXugj7qGqgSR7OaPgH80DacNw8K1adkJnbR7=" fullword ascii /* score: '4.00'*/
      $s131 = "XRdm6v7D" fullword ascii /* score: '4.00'*/
      $s132 = "OM0k6LLzQLZy" fullword ascii /* score: '4.00'*/
      $s133 = "=-=5=G=O=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s134 = "TK4rPQOkL7drbx6j7rW=" fullword ascii /* score: '4.00'*/
      $s135 = "PsJoHoO5Eoh9MG==" fullword ascii /* score: '4.00'*/
      $s136 = "XvKkUvCkL70obNBr8Mm=" fullword ascii /* score: '4.00'*/
      $s137 = "M837MMft5HN=" fullword ascii /* score: '4.00'*/
      $s138 = "Vvy98SLpCr09XG==" fullword ascii /* score: '4.00'*/
      $s139 = "XPdwQubFLp0hRMdl7raocZVYXugj7qGqgSS3LSTC4r0zbvRn7sPecZ1aRMkq7KYt2MO3PRfp3LBlPc1uTLXndt==" fullword ascii /* score: '4.00'*/
      $s140 = "L8FcE8z4216q TN2CIG6KfUeZvYmDE==" fullword ascii /* score: '4.00'*/
      $s141 = "fRmb7vuDDn p wo=" fullword ascii /* score: '4.00'*/
      $s142 = "XwOlUSHl3ZWmbwxe" fullword ascii /* score: '4.00'*/
      $s143 = "dR0o7bTwDENzXwpu" fullword ascii /* score: '4.00'*/
      $s144 = "CMPQPQ" fullword ascii /* score: '3.50'*/
      $s145 = "system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.42'*/ /* Goodware String - occured 1577 times */
      $s146 = " delete" fullword ascii /* score: '3.00'*/
      $s147 = ";1#INF" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s148 = "07c6bc37dc50874878dcb010336ed906" ascii /* score: '3.00'*/
      $s149 = "9de88c4009318ef1202283857f94e673" ascii /* score: '3.00'*/
      $s150 = ".?AV?$_Func_base@E$$V@std@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s151 = ".?AV?$_CancellationTokenCallback@V<lambda_3b8ab8d2629adf61a42ee3fe177a046b>@@@details@Concurrency@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s152 = "3b8ab8d2629adf61a42ee3fe177a046b" ascii /* score: '3.00'*/
      $s153 = "7c33b2c4310ad8c6be497d7a2a561bb8" ascii /* score: '3.00'*/
      $s154 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s155 = "eb87dfd73f857f44e1a351ea42ce2b34" ascii /* score: '3.00'*/
      $s156 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s157 = "0456396a71e3abd88ede77bdd2823d8e" ascii /* score: '3.00'*/
      $s158 = "5e5ab22ea98f4361dbf159481d01f54d" ascii /* score: '3.00'*/
      $s159 = ".?AV<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s160 = "Eja-JP" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s161 = "5>6J6k6" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s162 = "<_=h=p=" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s163 = ":0:@:D:L:d:t:x:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s164 = ">,><>@>T>X>h>l>p>x>" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s165 = ":;:I:u:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s166 = "0:0U0t0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s167 = "d0f1609e2fff913c5fc0b879a0d56e06" ascii /* score: '3.00'*/
      $s168 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s169 = "3 4(40484@4H4P4X4`4h4p4x4" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s170 = "141W1z1" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s171 = "6,646@6t6x6" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s172 = "D8(Ht'" fullword ascii /* score: '1.00'*/
      $s173 = " new[]" fullword ascii /* score: '1.00'*/
      $s174 = "u kE$<" fullword ascii /* score: '1.00'*/
      $s175 = ":u\"f9z" fullword ascii /* score: '1.00'*/
      $s176 = "UTF-16LEUNICODE" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s177 = "CM @PRj" fullword ascii /* score: '1.00'*/
      $s178 = "<=upG8" fullword ascii /* score: '1.00'*/
      $s179 = "zSSSSj" fullword ascii /* score: '1.00'*/
      $s180 = "<at.<rt!<wt" fullword ascii /* score: '1.00'*/
      $s181 = "api-ms-" fullword wide /* score: '1.00'*/
      $s182 = "ext-ms-" fullword wide /* score: '1.00'*/
      $s183 = "2G2Q2[2r2|2" fullword ascii /* score: '1.00'*/
      $s184 = "8G8Q8[8r8|8" fullword ascii /* score: '1.00'*/
      $s185 = "Sk{$4kK(4" fullword ascii /* score: '1.00'*/
      $s186 = "h1p1x1|1" fullword ascii /* score: '1.00'*/
      $s187 = "6G6Q6[6r6|6" fullword ascii /* score: '1.00'*/
      $s188 = "2 2$2(2,2024282<2@2D2H2L2P2T2X2\\2`2d2(7,7074787<7@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7" fullword ascii /* score: '1.00'*/
      $s189 = ":2:<:g:q:{:" fullword ascii /* score: '1.00'*/
      $s190 = "7'818;8R8\\8" fullword ascii /* score: '1.00'*/
      $s191 = ".?AV_DefaultPPLTaskScheduler@details@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s192 = "20242`7d7h7l7p7t7x7|7" fullword ascii /* score: '1.00'*/
      $s193 = "=2=<=g=q={=" fullword ascii /* score: '1.00'*/
      $s194 = ">2><>g>q>{>" fullword ascii /* score: '1.00'*/
      $s195 = ";{dv(2" fullword ascii /* score: '1.00'*/
      $s196 = "1 1$1(1,1014181<1@1T1X1\\1`1d1h1l1p1t1x1|1" fullword ascii /* score: '1.00'*/
      $s197 = "6'717;7R7\\7" fullword ascii /* score: '1.00'*/
      $s198 = "9G9Q9[9r9|9" fullword ascii /* score: '1.00'*/
      $s199 = "<G<Q<[<r<|<" fullword ascii /* score: '1.00'*/
      $s200 = ";'<1<;<R<\\<" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c {
   meta:
      description = "Amadey_MALW - file 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s4 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "61666C6}6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'aflf' */
      $s7 = ";(</<4<8<<<@<" fullword ascii /* score: '9.00'*/ /* hex encoded string 'H' */
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s9 = "RxCmdx==" fullword ascii /* score: '7.00'*/
      $s10 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s11 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s12 = "vector too long" fullword ascii /* score: '6.00'*/
      $s13 = "list too long" fullword ascii /* score: '6.00'*/
      $s14 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s15 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" fullword ascii /* score: '5.00'*/
      $s16 = ".?AV?$_Func_impl_no_alloc@V?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@X$$V@std@@" fullword ascii /* score: '5.00'*/
      $s17 = "DgSkbUN9" fullword ascii /* score: '5.00'*/
      $s18 = "FWCRbTS0" fullword ascii /* score: '5.00'*/
      $s19 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s20 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s21 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s22 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s23 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s24 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s25 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s26 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s27 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s28 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s29 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s30 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s31 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
      $s32 = "WWWSHSh" fullword ascii /* score: '4.00'*/
      $s33 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s34 = " delete[]" fullword ascii /* score: '4.00'*/
      $s35 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s36 = "WPWWWS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s37 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s38 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s39 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" fullword ascii /* score: '4.00'*/
      $s40 = "cy@@@?$task@E@Concurrency@@U_TaskProcHandle@details@3@@details@Concurrency@@" fullword ascii /* score: '4.00'*/
      $s41 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" fullword ascii /* score: '4.00'*/
      $s42 = ".?AV_ExceptionPtr_normal@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s43 = ".?AV?$_Func_impl_no_alloc@V<lambda_0456396a71e3abd88ede77bdd2823d8e>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s44 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s45 = ".?AV?$_Ref_count_obj2@U_ExceptionHolder@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s46 = ".?AV?$_Func_impl_no_alloc@V<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@E$$V@std@@" fullword ascii /* score: '4.00'*/
      $s47 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s48 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s49 = ".?AV?$_Func_impl_no_alloc@V<lambda_9de88c4009318ef1202283857f94e673>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s50 = ".?AV?$_Ref_count_obj2@U?$_Task_impl@E@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s51 = "FYY;w(|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s52 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s53 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s54 = "rrency@@" fullword ascii /* score: '4.00'*/
      $s55 = ".?AV?$_Task_async_state@X@std@@" fullword ascii /* score: '4.00'*/
      $s56 = ".?AV?$_Func_impl_no_alloc@V<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s57 = "Wj4XPV" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s58 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s59 = "YYF;w,|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s60 = ".?AV?$_Func_impl_no_alloc@V<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s61 = "Eapi-ms-win-core-fibers-l1-1-1" fullword wide /* score: '4.00'*/
      $s62 = "Eapi-ms-win-core-datetime-l1-1-1" fullword wide /* score: '4.00'*/
      $s63 = "7VebcDtzHm g6Hy=" fullword ascii /* score: '4.00'*/
      $s64 = "SVYaJz6DDJOJLFnXzs1rD1Bd" fullword ascii /* score: '4.00'*/
      $s65 = "KWSodjSu9IOX5Xzp" fullword ascii /* score: '4.00'*/
      $s66 = "OUiJWBSNSISr6oTD3SpLRVNtMwJ6QROv8fi 0UKcLqKv5XPJ2NFo4EC2Xy3iVvOs" fullword ascii /* score: '4.00'*/
      $s67 = "GcxnOd==" fullword ascii /* score: '4.00'*/
      $s68 = "0 0$0(0,000X0\\0`0d0h0l0p0t0x0|0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s69 = "?(?8?D?d?l?t?|?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s70 = "LOKvWx==" fullword ascii /* score: '4.00'*/
      $s71 = "7VeReDOv969cFYOlCNI9Ey==" fullword ascii /* score: '4.00'*/
      $s72 = "xJmtcZ20U0 WFVTu4Ttn50iXaPcnK8uj6WGjMTOh9KJ3CH7m3MM1AkOedzIbKnuj5PubcjCtUX5e" fullword ascii /* score: '4.00'*/
      $s73 = "CgO8dZqr60CoCDarzs1h4Qxf" fullword ascii /* score: '4.00'*/
      $s74 = "484a4z4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s75 = "?6?L?k?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s76 = "NPCfcd==" fullword ascii /* score: '4.00'*/
      $s77 = "DLYieN==" fullword ascii /* score: '4.00'*/
      $s78 = "7gSk0DusHDNqTYjq" fullword ascii /* score: '4.00'*/
      $s79 = "5AOQdAlvGA==" fullword ascii /* score: '4.00'*/
      $s80 = "xJljMPXtGW5=" fullword ascii /* score: '4.00'*/
      $s81 = "CbxcKfy0606h64X5ztw9BgVdZzZlEp==" fullword ascii /* score: '4.00'*/
      $s82 = "CbxcKfyyU09c" fullword ascii /* score: '4.00'*/
      $s83 = "LzScZUSs9JSh8ITu3c6rDjiPZQRo8wOX5P6k" fullword ascii /* score: '4.00'*/
      $s84 = "FTObcQarQLZr5X7pQN9m5Eet" fullword ascii /* score: '4.00'*/
      $s85 = "OAGl0ESj9I d6XW=" fullword ascii /* score: '4.00'*/
      $s86 = "<B=T=f=x=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s87 = "SWGb0z2k7KC4S3zu4sXc4Eu5" fullword ascii /* score: '4.00'*/
      $s88 = "5VSocjSsHDNqTHzx" fullword ascii /* score: '4.00'*/
      $s89 = "GsBkOABuHnVWFkGB" fullword ascii /* score: '4.00'*/
      $s90 = "FQSkbTKvUKZp" fullword ascii /* score: '4.00'*/
      $s91 = "5AOQdEJ6GCc=" fullword ascii /* score: '4.00'*/
      $s92 = "KOWrVYNgP6di8Ifm4cM=" fullword ascii /* score: '4.00'*/
      $s93 = "SPG 0DSmU6ml5nvx3MXn5FCvcWVU c719QlmNQFzIHZYHAi CL0=" fullword ascii /* score: '4.00'*/
      $s94 = "CvVcJx==" fullword ascii /* score: '4.00'*/
      $s95 = "FLXjMPXt" fullword ascii /* score: '4.00'*/
      $s96 = "DOSJSSGQPodCMVzKAG==" fullword ascii /* score: '4.00'*/
      $s97 = "7WWleUOzUW h9HW=" fullword ascii /* score: '4.00'*/
      $s98 = "URPQQh@]C" fullword ascii /* score: '4.00'*/
      $s99 = "OAGl00Gh7YWd8HHh" fullword ascii /* score: '4.00'*/
      $s100 = "KfiQ0DSmU0 gTYK=" fullword ascii /* score: '4.00'*/
      $s101 = "=$=(=@=P=T=h=l=|=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s102 = "GcxoNd==" fullword ascii /* score: '4.00'*/
      $s103 = "OUiJWBSNSISX7oLq3dJv402XcfclQROXRxKlckOy76C9K3ay4xNSRVGLYP5eTtGs6QyReDSyOqKpTR==" fullword ascii /* score: '4.00'*/
      $s104 = "OAGl00Gh71R=" fullword ascii /* score: '4.00'*/
      $s105 = "4)4i4o4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s106 = "0$080H0l0x0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s107 = "869Y9|9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s108 = "MVCpdDSy86y1CFzmP7==" fullword ascii /* score: '4.00'*/
      $s109 = "PVikSDSmU0 gTYK=" fullword ascii /* score: '4.00'*/
      $s110 = "0T1X1`1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s111 = "Lz6 eD6yDJihSh==" fullword ascii /* score: '4.00'*/
      $s112 = "6 6(6@6D6\\6l6p6t6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s113 = "7WNZdt==" fullword ascii /* score: '4.00'*/
      $s114 = "GcxnPN==" fullword ascii /* score: '4.00'*/
      $s115 = "KQWfdjB=" fullword ascii /* score: '4.00'*/
      $s116 = "Ffmm0t==" fullword ascii /* score: '4.00'*/
      $s117 = "OzCk0DBgP60f8YLu5xc=" fullword ascii /* score: '4.00'*/
      $s118 = "FPSU0TK19Kqr6oDA3wdb7QyvZP5o vOw5Pak0TNgGY4l6HWlz7==" fullword ascii /* score: '4.00'*/
      $s119 = "> >$>(>,>@>D>T>X>h>l>p>x>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s120 = "4G5\\5e5n5" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s121 = "/SPPWhfxB" fullword ascii /* score: '4.00'*/
      $s122 = "4 484<4T4d4h4|4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s123 = "GwBoNwN1Inh0IR==" fullword ascii /* score: '4.00'*/
      $s124 = ":X;h;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s125 = "7gSk0DusHDNc" fullword ascii /* score: '4.00'*/
      $s126 = "SWGb0z2k7KB=" fullword ascii /* score: '4.00'*/
      $s127 = "GzRU0Ax4InWdSR==" fullword ascii /* score: '4.00'*/
      $s128 = "OrXbcERt" fullword ascii /* score: '4.00'*/
      $s129 = "KV6keDSu9G6Q9YDqF9tl6UuXaQFa9cJsTf6ocPYkT1WdIzDn3TNmRECveM4mHHTq" fullword ascii /* score: '4.00'*/
      $s130 = "KV6keDSu9G6Q9YDqF9t 5FypaPRa ves6b6UMUa39C6i64LyCNNq4ESrYVcdVLJ=" fullword ascii /* score: '4.00'*/
      $s131 = ">%>9>e>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s132 = "LVSQUjC0614hO4nE5wNlKU2jbp==" fullword ascii /* score: '4.00'*/
      $s133 = "Pfia0T6JME==" fullword ascii /* score: '4.00'*/
      $s134 = "FLXDDd==" fullword ascii /* score: '4.00'*/
      $s135 = "SVufdz2k7KB=" fullword ascii /* score: '4.00'*/
      $s136 = "FUyieTap7rRr" fullword ascii /* score: '4.00'*/
      $s137 = "FLSieN==" fullword ascii /* score: '4.00'*/
      $s138 = "LzScZUSs9JSh8ITu3c6rDjePZQRo8wOX5P6k" fullword ascii /* score: '4.00'*/
      $s139 = "OUiJWBSNSISX7oLq3dJv402XcfclQROXRxKlckOy76C9PX7u5wNcNkihZPc6MP2LPyGFUCuWNYWBN2y=" fullword ascii /* score: '4.00'*/
      $s140 = "8$8D8L8T8X8`8t8|8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s141 = "9;:V:q:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s142 = "GsVmWD60T0CPTXP64cdS7O==" fullword ascii /* score: '4.00'*/
      $s143 = "RwxmNAx=" fullword ascii /* score: '4.00'*/
      $s144 = "DbV7SUep9GN=" fullword ascii /* score: '4.00'*/
      $s145 = "KV6jdES0U1OKSX3q" fullword ascii /* score: '4.00'*/
      $s146 = "CMPQPQ" fullword ascii /* score: '3.50'*/
      $s147 = "system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.42'*/ /* Goodware String - occured 1577 times */
      $s148 = " delete" fullword ascii /* score: '3.00'*/
      $s149 = ";1#INF" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s150 = "9de88c4009318ef1202283857f94e673" ascii /* score: '3.00'*/
      $s151 = ".?AV?$_Func_base@E$$V@std@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s152 = ".?AV?$_CancellationTokenCallback@V<lambda_3b8ab8d2629adf61a42ee3fe177a046b>@@@details@Concurrency@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s153 = "3b8ab8d2629adf61a42ee3fe177a046b" ascii /* score: '3.00'*/
      $s154 = "7c33b2c4310ad8c6be497d7a2a561bb8" ascii /* score: '3.00'*/
      $s155 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s156 = "eb87dfd73f857f44e1a351ea42ce2b34" ascii /* score: '3.00'*/
      $s157 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s158 = "0456396a71e3abd88ede77bdd2823d8e" ascii /* score: '3.00'*/
      $s159 = "5e5ab22ea98f4361dbf159481d01f54d" ascii /* score: '3.00'*/
      $s160 = ".?AV<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s161 = "Eja-JP" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s162 = "5481b88a6ef75bcf21333988a4e47048" ascii /* score: '3.00'*/
      $s163 = "<<<X<x<" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s164 = "0dbe903ae9d22887a807d475e820d898" ascii /* score: '3.00'*/
      $s165 = "979]9x9" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s166 = "30484@4H4P4X4`4h4p4x4" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s167 = "011T1o1" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s168 = "006700e5a2ab05704bbb0c589b88924d" ascii /* score: '3.00'*/
      $s169 = "?#?c?u?" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s170 = "6$6<6L6P6X6p6" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s171 = "7<7D7L7X7|7" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s172 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s173 = ":':F:e:" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s174 = "2 2@2L2t2" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s175 = "4 5f5u5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s176 = ">$>(>8><>@>H>`>d>|>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s177 = ":$:(:,:4:L:\\:`:h:" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s178 = "<)=h=u=" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s179 = "00080@0" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s180 = "676A6K6b6l6" fullword ascii /* score: '1.00'*/
      $s181 = "D8(Ht'" fullword ascii /* score: '1.00'*/
      $s182 = ";7;A;K;b;l;" fullword ascii /* score: '1.00'*/
      $s183 = "<!<+<B<L<w<" fullword ascii /* score: '1.00'*/
      $s184 = "4\"4,4W4a4k4" fullword ascii /* score: '1.00'*/
      $s185 = "7!7+7B7L7w7" fullword ascii /* score: '1.00'*/
      $s186 = "171A1K1b1l1" fullword ascii /* score: '1.00'*/
      $s187 = ";\";,;W;a;k;" fullword ascii /* score: '1.00'*/
      $s188 = ":\":,:W:a:k:" fullword ascii /* score: '1.00'*/
      $s189 = "9\"9,9W9a9k9" fullword ascii /* score: '1.00'*/
      $s190 = "5!5+5B5L5w5" fullword ascii /* score: '1.00'*/
      $s191 = "=\"=,=W=a=k=" fullword ascii /* score: '1.00'*/
      $s192 = " new[]" fullword ascii /* score: '1.00'*/
      $s193 = ";!;+;B;L;w;" fullword ascii /* score: '1.00'*/
      $s194 = "8\"8,8W8a8k8" fullword ascii /* score: '1.00'*/
      $s195 = "474A4K4b4l4" fullword ascii /* score: '1.00'*/
      $s196 = "?!?+?B?L?w?" fullword ascii /* score: '1.00'*/
      $s197 = "6\"6,6W6a6k6" fullword ascii /* score: '1.00'*/
      $s198 = ":7:A:K:b:l:" fullword ascii /* score: '1.00'*/
      $s199 = "2!2+2B2L2w2" fullword ascii /* score: '1.00'*/
      $s200 = ":!:+:B:L:w:" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226 {
   meta:
      description = "Amadey_MALW - file 919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s4 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = ";$;-;6;a;" fullword ascii /* score: '9.00'*/ /* hex encoded string 'j' */
      $s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s8 = ":$:,:0:8:L:T:\\:h:" fullword ascii /* score: '7.00'*/
      $s9 = "9':1:;:R:\\:" fullword ascii /* score: '7.00'*/
      $s10 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s11 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s12 = "vector too long" fullword ascii /* score: '6.00'*/
      $s13 = "list too long" fullword ascii /* score: '6.00'*/
      $s14 = "031931f55cda562b77b679daeb0c350c" ascii /* score: '6.00'*/
      $s15 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s16 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" fullword ascii /* score: '5.00'*/
      $s17 = ".?AV?$_Func_impl_no_alloc@V?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@X$$V@std@@" fullword ascii /* score: '5.00'*/
      $s18 = "xlDeNcFCXM59" fullword ascii /* score: '5.00'*/
      $s19 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s20 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s21 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s22 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s23 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s24 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s25 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s26 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s27 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s28 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s29 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s30 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s31 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
      $s32 = "WWWSHSh" fullword ascii /* score: '4.00'*/
      $s33 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s34 = " delete[]" fullword ascii /* score: '4.00'*/
      $s35 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s36 = "WPWWWS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s37 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s38 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s39 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" fullword ascii /* score: '4.00'*/
      $s40 = "?$?4?8?L?P?`?d?h?p?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s41 = "cy@@@?$task@E@Concurrency@@U_TaskProcHandle@details@3@@details@Concurrency@@" fullword ascii /* score: '4.00'*/
      $s42 = "728?8M8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s43 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" fullword ascii /* score: '4.00'*/
      $s44 = "323<3g3q3{3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s45 = ".?AV_ExceptionPtr_normal@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s46 = ".?AV?$_Func_impl_no_alloc@V<lambda_0456396a71e3abd88ede77bdd2823d8e>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s47 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s48 = ".?AV?$_Ref_count_obj2@U_ExceptionHolder@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s49 = ".?AV?$_Func_impl_no_alloc@V<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@E$$V@std@@" fullword ascii /* score: '4.00'*/
      $s50 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s51 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s52 = ".?AV?$_Func_impl_no_alloc@V<lambda_9de88c4009318ef1202283857f94e673>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s53 = ".?AV?$_Ref_count_obj2@U?$_Task_impl@E@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s54 = "6$686@6H6T6t6|6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s55 = "FYY;w(|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s56 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s57 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s58 = "rrency@@" fullword ascii /* score: '4.00'*/
      $s59 = "4$444@4`4h4p4x4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s60 = ".?AV?$_Task_async_state@X@std@@" fullword ascii /* score: '4.00'*/
      $s61 = "1 1$14181H1L1\\1`1d1l1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s62 = ".?AV?$_Func_impl_no_alloc@V<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s63 = "Wj4XPV" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s64 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s65 = "YYF;w,|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s66 = ".?AV?$_Func_impl_no_alloc@V<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s67 = "Eapi-ms-win-core-fibers-l1-1-1" fullword wide /* score: '4.00'*/
      $s68 = "Eapi-ms-win-core-datetime-l1-1-1" fullword wide /* score: '4.00'*/
      $s69 = "1>2K2^2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s70 = "yl19VRltbsJ=" fullword ascii /* score: '4.00'*/
      $s71 = "xlDeNcF49M2d7ZXVxFCkDeSeWyPmBB==" fullword ascii /* score: '4.00'*/
      $s72 = "\"0M0n0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s73 = "MGDoQxE=" fullword ascii /* score: '4.00'*/
      $s74 = "<'=F=w=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s75 = "GJYe2RZwbvOd9DTk1obDFhbQWPHp5INP0Zbm" fullword ascii /* score: '4.00'*/
      $s76 = "Kpoc3QcNPq==" fullword ascii /* score: '4.00'*/
      $s77 = "J3QAZyJXQRN=" fullword ascii /* score: '4.00'*/
      $s78 = "0KUSgBQ Jo9=" fullword ascii /* score: '4.00'*/
      $s79 = "sTrlPM4xJI1=" fullword ascii /* score: '4.00'*/
      $s80 = "GYQxZu==" fullword ascii /* score: '4.00'*/
      $s81 = "F5blgBZ4XNKGTS3g" fullword ascii /* score: '4.00'*/
      $s82 = "NZMb3AZqXSih6ivn1Y3z7Dzw VLV7o6T40roQNMDLtVUIvi0AX6=" fullword ascii /* score: '4.00'*/
      $s83 = "BmDqQa==" fullword ascii /* score: '4.00'*/
      $s84 = "F3IvXzQkG7==" fullword ascii /* score: '4.00'*/
      $s85 = "yYYLVPNUSa yNQzAyS==" fullword ascii /* score: '4.00'*/
      $s86 = "A3Qq3QJ4XIBnPWObIWjSPRLDFu3HMzsmxFbMXcE=" fullword ascii /* score: '4.00'*/
      $s87 = "BGHqQtU5L dWJM==" fullword ascii /* score: '4.00'*/
      $s88 = ":&:F:S:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s89 = "3#4)4/454;4A4H4O4V4]4d4k4r4z4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s90 = "JKMn3XNl NN=" fullword ascii /* score: '4.00'*/
      $s91 = "05YqfgZwKpJmUCzn" fullword ascii /* score: '4.00'*/
      $s92 = "JJbV3RND9wWk7y7g4IS=" fullword ascii /* score: '4.00'*/
      $s93 = "1$151A1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s94 = "050g0m0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s95 = "GJYe2RZwbvOd9DTk1obDFhfQWPHp5INP0Zbm" fullword ascii /* score: '4.00'*/
      $s96 = "A5gggWVsKpmrGYnpOIT8Fjvm s==" fullword ascii /* score: '4.00'*/
      $s97 = "BmDpRa==" fullword ascii /* score: '4.00'*/
      $s98 = "JKMn3BZnbu6 7SW=" fullword ascii /* score: '4.00'*/
      $s99 = "xlDnVa==" fullword ascii /* score: '4.00'*/
      $s100 = "OZQgfsF3duOtLWzOxEG=" fullword ascii /* score: '4.00'*/
      $s101 = "F5bmhAZybs2M TDgDkzl7Dvq8OHb7Hdk1lbWPRh7bo2e7ZLoAZTC6CPsVU3eSXI=" fullword ascii /* score: '4.00'*/
      $s102 = "BWjTPdI7K95pHfipBVi=" fullword ascii /* score: '4.00'*/
      $s103 = "A4EkhQht dNn" fullword ascii /* score: '4.00'*/
      $s104 = "xFbw3QBpbwV9GXTJxEG=" fullword ascii /* score: '4.00'*/
      $s105 = "JHbLZu==" fullword ascii /* score: '4.00'*/
      $s106 = "AZYW3QR5bwmn7jDq1Ijn9OvwWOVp7HNo0Zgm3QUkJK0h7CWbxi==" fullword ascii /* score: '4.00'*/
      $s107 = "J4oLZyZRVuOn7jTt14vXTTKuJvz7N3Nn3pob3RRgOcGr6SPz0ZLA6Cz3UxTjSHNk" fullword ascii /* score: '4.00'*/
      $s108 = "J3byZzhFSaW5OSne2o7D6YTYUx8j5nJk36P9XfVgOTWq8iXp3HXp7jHn9UY=" fullword ascii /* score: '4.00'*/
      $s109 = "0!0e0r0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s110 = "xlDnYwEm" fullword ascii /* score: '4.00'*/
      $s111 = "MHIogu==" fullword ascii /* score: '4.00'*/
      $s112 = "?.?B?U?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s113 = "FY2tYVUkSS e9Dfc2oS=" fullword ascii /* score: '4.00'*/
      $s114 = "#0K0n0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s115 = "JJIm3AIkSSWb9TLk3Ji=" fullword ascii /* score: '4.00'*/
      $s116 = "BmDpSK==" fullword ascii /* score: '4.00'*/
      $s117 = "DoLaMwcJ" fullword ascii /* score: '4.00'*/
      $s118 = "N6Md3w9o wy0TYzk2E3o6Cr6" fullword ascii /* score: '4.00'*/
      $s119 = "F5bmhAZybs2M TDgDkzx8SrY8Pvb6oIkOpbqfM5oWNS JuDd15TyTCzwbLUnETSi" fullword ascii /* score: '4.00'*/
      $s120 = "A0YmeQRzXwVl" fullword ascii /* score: '4.00'*/
      $s121 = "AVYkhK==" fullword ascii /* score: '4.00'*/
      $s122 = "xqU gWxv9MykDyahxE7t6Oug" fullword ascii /* score: '4.00'*/
      $s123 = "IZIhfa==" fullword ascii /* score: '4.00'*/
      $s124 = "N5Tp3dI5LcRUIs==" fullword ascii /* score: '4.00'*/
      $s125 = "2qYm3ABwKpJ9" fullword ascii /* score: '4.00'*/
      $s126 = "JKMn3XNl KS 9CH8" fullword ascii /* score: '4.00'*/
      $s127 = "25kThAVzbS59GTObAZOkGw==" fullword ascii /* score: '4.00'*/
      $s128 = "BC1oZAc4WMyLUSPW2oj49M==" fullword ascii /* score: '4.00'*/
      $s129 = "J4oLZyZRVuOT8jLg1pPH6YZY e3mN3NPMHQnfhVC Sy5QS7k3IToPifiWO37J11DKIMHXzB0QKSxOXy=" fullword ascii /* score: '4.00'*/
      $s130 = "yqYmeRUc" fullword ascii /* score: '4.00'*/
      $s131 = "0KUSgxszJm==" fullword ascii /* score: '4.00'*/
      $s132 = "K0UriRRnJcWWUM==" fullword ascii /* score: '4.00'*/
      $s133 = "N54cMwcHGvKFMAnNxE7DFZye" fullword ascii /* score: '4.00'*/
      $s134 = "2qYm3ABwKpJmUTjg" fullword ascii /* score: '4.00'*/
      $s135 = "F6YqggZybuKT6Szf" fullword ascii /* score: '4.00'*/
      $s136 = "?[?o?t?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s137 = "GJbbhAcCGvedTc==" fullword ascii /* score: '4.00'*/
      $s138 = "?\"?4?<?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s139 = "IpbqhAcy" fullword ascii /* score: '4.00'*/
      $s140 = "xj3CUWcybwWm9y3P4ZzpIevf zvm4XF73JonfcczWTSd9y3u3JHpSSULz9UE" fullword ascii /* score: '4.00'*/
      $s141 = "G5YSXgJ49N0dPZnu3ITxMSZk9o==" fullword ascii /* score: '4.00'*/
      $s142 = "FpoS3AZqXM6cUTK=" fullword ascii /* score: '4.00'*/
      $s143 = "Apso3q==" fullword ascii /* score: '4.00'*/
      $s144 = "<.<b<k<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s145 = "9#9)9.949:9?9E9K9P9V9\\9a9g9m9r9x9~9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s146 = "J4oLZyZRVuOT8jLg1pPH6YZY e3mN3NPMHQnfhVC Sy5LYao2JT4TTDMVOVfQFFk10EThAZCRcGlUM==" fullword ascii /* score: '4.00'*/
      $s147 = "sTsvfW94XM6SGQTk25zz7YfY8O3oHjtb16MlPQVlbwFZDC7c1YScCiLfayycHztb0ZAdfgJxXJ1a" fullword ascii /* score: '4.00'*/
      $s148 = "xFbMYcEm" fullword ascii /* score: '4.00'*/
      $s149 = "K5omVAZqXM6cUTK=" fullword ascii /* score: '4.00'*/
      $s150 = "25kdfAADK96c7Cy=" fullword ascii /* score: '4.00'*/
      $s151 = "system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.42'*/ /* Goodware String - occured 1577 times */
      $s152 = " delete" fullword ascii /* score: '3.00'*/
      $s153 = ";1#INF" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s154 = "07c6bc37dc50874878dcb010336ed906" ascii /* score: '3.00'*/
      $s155 = "9de88c4009318ef1202283857f94e673" ascii /* score: '3.00'*/
      $s156 = ".?AV?$_Func_base@E$$V@std@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s157 = ".?AV?$_CancellationTokenCallback@V<lambda_3b8ab8d2629adf61a42ee3fe177a046b>@@@details@Concurrency@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s158 = "3b8ab8d2629adf61a42ee3fe177a046b" ascii /* score: '3.00'*/
      $s159 = "7c33b2c4310ad8c6be497d7a2a561bb8" ascii /* score: '3.00'*/
      $s160 = "50585@5" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s161 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s162 = "eb87dfd73f857f44e1a351ea42ce2b34" ascii /* score: '3.00'*/
      $s163 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s164 = "8p9V:h:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s165 = "0456396a71e3abd88ede77bdd2823d8e" ascii /* score: '3.00'*/
      $s166 = "?0?K?c?" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s167 = "5e5ab22ea98f4361dbf159481d01f54d" ascii /* score: '3.00'*/
      $s168 = ".?AV<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s169 = "Eja-JP" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s170 = "0dd3e5ee91b367c60c9e575983554b30" ascii /* score: '3.00'*/
      $s171 = "2-2N2`2" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s172 = "6>6]6p6" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s173 = "7&787}7" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s174 = "1Y1d1v1" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s175 = "5*6V6h6" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s176 = "484_4p4" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s177 = "343A3d3" ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s178 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s179 = "3 4(40484@4H4P4X4`4h4p4x4" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s180 = "D8(Ht'" fullword ascii /* score: '1.00'*/
      $s181 = " new[]" fullword ascii /* score: '1.00'*/
      $s182 = "u kE$<" fullword ascii /* score: '1.00'*/
      $s183 = ":u\"f9z" fullword ascii /* score: '1.00'*/
      $s184 = "UTF-16LEUNICODE" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s185 = "CM @PRj" fullword ascii /* score: '1.00'*/
      $s186 = "<=upG8" fullword ascii /* score: '1.00'*/
      $s187 = "zSSSSj" fullword ascii /* score: '1.00'*/
      $s188 = "<at.<rt!<wt" fullword ascii /* score: '1.00'*/
      $s189 = "api-ms-" fullword wide /* score: '1.00'*/
      $s190 = "ext-ms-" fullword wide /* score: '1.00'*/
      $s191 = "4 4(4,40484L4T4X4`4t4|4" fullword ascii /* score: '1.00'*/
      $s192 = "2G2Q2[2r2|2" fullword ascii /* score: '1.00'*/
      $s193 = "8G8Q8[8r8|8" fullword ascii /* score: '1.00'*/
      $s194 = "Sk{$4kK(4" fullword ascii /* score: '1.00'*/
      $s195 = "3V3a3F4U4" fullword ascii /* score: '1.00'*/
      $s196 = "h1p1x1|1" fullword ascii /* score: '1.00'*/
      $s197 = "=&?7?}?" fullword ascii /* score: '1.00'*/
      $s198 = "6 606@6D6T6X6\\6p6t6x6" fullword ascii /* score: '1.00'*/
      $s199 = "141<1D1L1|1" fullword ascii /* score: '1.00'*/
      $s200 = "6G6Q6[6r6|6" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_6738c904ba78a2268a8950152a6c7448 {
   meta:
      description = "Amadey_MALW - file 6738c904ba78a2268a8950152a6c7448"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "42054b960727fbd72bde57e8903881e4239e9500f1160ca298e10a1b438698a8"
   strings:
      $s1 = "BinaryMethodCa.exe" fullword wide /* score: '21.00'*/
      $s2 = "https://sectigo.com/CPS0D" fullword ascii /* score: '17.00'*/
      $s3 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii /* score: '16.00'*/
      $s4 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii /* score: '16.00'*/
      $s5 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s6 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
      $s7 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t" fullword ascii /* score: '13.00'*/
      $s8 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#" fullword ascii /* score: '13.00'*/
      $s9 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s10 = "      <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s11 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s12 = "      <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s13 = "      <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s14 = "      <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s15 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s16 = "             requestedExecutionLevel " fullword ascii /* score: '11.00'*/
      $s17 = "            requestedExecutionLevel " fullword ascii /* score: '11.00'*/
      $s18 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s19 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s20 = "          processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s21 = " .NET Framework 4.6" fullword ascii /* score: '10.00'*/
      $s22 = "V -s  =" fullword ascii /* score: '9.00'*/
      $s23 = "?4]| `4\\" fullword ascii /* score: '9.00'*/ /* hex encoded string 'D' */
      $s24 = "* 9L4?N,L" fullword ascii /* score: '9.00'*/
      $s25 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s26 = "YliL+ b," fullword ascii /* score: '8.00'*/
      $s27 = "  <!-- Windows " fullword ascii /* score: '8.00'*/
      $s28 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s29 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s30 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" fullword ascii /* score: '7.00'*/
      $s31 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" fullword ascii /* score: '7.00'*/
      $s32 = "#Sectigo RSA Time Stamping Signer #2" fullword ascii /* score: '7.00'*/
      $s33 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii /* score: '7.00'*/
      $s34 = "#Sectigo RSA Time Stamping Signer #20" fullword ascii /* score: '7.00'*/
      $s35 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" fullword ascii /* score: '7.00'*/
      $s36 = "  </compatibility>" fullword ascii /* score: '7.00'*/
      $s37 = "yT:\\EQ" fullword ascii /* score: '7.00'*/
      $s38 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" fullword ascii /* score: '7.00'*/
      $s39 = "hGI.LAJ';L" fullword ascii /* score: '7.00'*/
      $s40 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" fullword ascii /* score: '7.00'*/
      $s41 = "CCDCFCH" fullword ascii /* score: '6.50'*/
      $s42 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s43 = "Sectigo Limited1,0*" fullword ascii /* score: '6.00'*/
      $s44 = "Cvpxcpkr" fullword ascii /* score: '6.00'*/
      $s45 = "Sectigo Limited1%0#" fullword ascii /* score: '6.00'*/
      $s46 = "!!!5iii" fullword ascii /* score: '6.00'*/
      $s47 = "y~m#:^CmD" fullword ascii /* score: '6.00'*/
      $s48 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s49 = ")- L~}" fullword ascii /* score: '5.00'*/
      $s50 = "s /jO@h" fullword ascii /* score: '5.00'*/
      $s51 = "AKOWqL8" fullword ascii /* score: '5.00'*/
      $s52 = "SmCBnZm6" fullword ascii /* score: '5.00'*/
      $s53 = "KqLajE4" fullword ascii /* score: '5.00'*/
      $s54 = "$Q\"L -y" fullword ascii /* score: '5.00'*/
      $s55 = "CmcpjXm9" fullword ascii /* score: '5.00'*/
      $s56 = "jGprSy4" fullword ascii /* score: '5.00'*/
      $s57 = "  <!-- " fullword ascii /* score: '5.00'*/
      $s58 = "pzKZ717" fullword ascii /* score: '5.00'*/
      $s59 = "2+ lL{" fullword ascii /* score: '5.00'*/
      $s60 = "+ j>LI" fullword ascii /* score: '5.00'*/
      $s61 = "lnzrpp" fullword ascii /* score: '5.00'*/
      $s62 = "cC+ cj" fullword ascii /* score: '5.00'*/
      $s63 = "yvnizg4" fullword ascii /* score: '5.00'*/
      $s64 = "\\QZVFks!" fullword ascii /* score: '5.00'*/
      $s65 = "|D- {3" fullword ascii /* score: '5.00'*/
      $s66 = "sG%ra%" fullword ascii /* score: '5.00'*/
      $s67 = "mQHKFB0" fullword ascii /* score: '5.00'*/
      $s68 = "r]hlL+ " fullword ascii /* score: '5.00'*/
      $s69 = "BeTHLI3" fullword ascii /* score: '5.00'*/
      $s70 = "XmrafCmL0" fullword ascii /* score: '5.00'*/
      $s71 = "y1hL+ ?-" fullword ascii /* score: '5.00'*/
      $s72 = "YtypDT1" fullword ascii /* score: '5.00'*/
      $s73 = "eJNxUM9" fullword ascii /* score: '5.00'*/
      $s74 = "$ /bPW" fullword ascii /* score: '5.00'*/
      $s75 = "qTxYTh9" fullword ascii /* score: '5.00'*/
      $s76 = "M6*m- " fullword ascii /* score: '5.00'*/
      $s77 = "8;,u* " fullword ascii /* score: '5.00'*/
      $s78 = "|A -BH" fullword ascii /* score: '5.00'*/
      $s79 = "m* o&{'vq" fullword ascii /* score: '5.00'*/
      $s80 = "=F6W- " fullword ascii /* score: '5.00'*/
      $s81 = "pCuLryM0" fullword ascii /* score: '5.00'*/
      $s82 = "BfSsS64" fullword ascii /* score: '5.00'*/
      $s83 = "r]T6L+ :#L" fullword ascii /* score: '5.00'*/
      $s84 = "jbOaZe8" fullword ascii /* score: '5.00'*/
      $s85 = "CjsX -" fullword ascii /* score: '5.00'*/
      $s86 = "C\"G%s%0" fullword ascii /* score: '5.00'*/
      $s87 = "oMNNcC4" fullword ascii /* score: '5.00'*/
      $s88 = "YD& /m]" fullword ascii /* score: '5.00'*/
      $s89 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s90 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s91 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s92 = "atFqm)S" fullword ascii /* score: '4.00'*/
      $s93 = "3haSD1$$f" fullword ascii /* score: '4.00'*/
      $s94 = "$vStTmgI" fullword ascii /* score: '4.00'*/
      $s95 = "VmQn{]m" fullword ascii /* score: '4.00'*/
      $s96 = "lAbT!3,)" fullword ascii /* score: '4.00'*/
      $s97 = "YJGAll4p" fullword ascii /* score: '4.00'*/
      $s98 = "wLUzY(L" fullword ascii /* score: '4.00'*/
      $s99 = ">TFhKUwx4" fullword ascii /* score: '4.00'*/
      $s100 = " Windows" fullword ascii /* score: '4.00'*/
      $s101 = ">ytmD6Lj" fullword ascii /* score: '4.00'*/
      $s102 = "cenz}#0" fullword ascii /* score: '4.00'*/
      $s103 = "@RmRKNCm" fullword ascii /* score: '4.00'*/
      $s104 = "OTQA_Iy" fullword ascii /* score: '4.00'*/
      $s105 = "sQEV\"X" fullword ascii /* score: '4.00'*/
      $s106 = "9Lnef,L]" fullword ascii /* score: '4.00'*/
      $s107 = "aPCvtg/" fullword ascii /* score: '4.00'*/
      $s108 = ";Libl.LR" fullword ascii /* score: '4.00'*/
      $s109 = "XmsP%Am" fullword ascii /* score: '4.00'*/
      $s110 = "*rBoy[O|" fullword ascii /* score: '4.00'*/
      $s111 = "mAnz?L83" fullword ascii /* score: '4.00'*/
      $s112 = "BZiU\"a" fullword ascii /* score: '4.00'*/
      $s113 = "XBmJY?Ym4" fullword ascii /* score: '4.00'*/
      $s114 = "*X@jTbGS=&" fullword ascii /* score: '4.00'*/
      $s115 = "ZSYWZ ~" fullword ascii /* score: '4.00'*/
      $s116 = "ayqa*m*wa|@" fullword ascii /* score: '4.00'*/
      $s117 = "OTfycL " fullword ascii /* score: '4.00'*/
      $s118 = "EDhd2jjO|F" fullword ascii /* score: '4.00'*/
      $s119 = "jNcjAdF" fullword ascii /* score: '4.00'*/
      $s120 = "wpeKs\\>~" fullword ascii /* score: '4.00'*/
      $s121 = "%USERTrust RSA Certification Authority0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s122 = "sgLpZ\\" fullword ascii /* score: '4.00'*/
      $s123 = "?LENi*LF" fullword ascii /* score: '4.00'*/
      $s124 = "RBnNf'<" fullword ascii /* score: '4.00'*/
      $s125 = "8v]%cOm" fullword ascii /* score: '4.00'*/
      $s126 = "pkZO$,6" fullword ascii /* score: '4.00'*/
      $s127 = "1(zYoKA'\"" fullword ascii /* score: '4.00'*/
      $s128 = "pShNQAV_j" fullword ascii /* score: '4.00'*/
      $s129 = "KKKk)))8" fullword ascii /* score: '4.00'*/
      $s130 = " VmSDK]m" fullword ascii /* score: '4.00'*/
      $s131 = "lk|.cQW" fullword ascii /* score: '4.00'*/
      $s132 = "HmaZsSm{" fullword ascii /* score: '4.00'*/
      $s133 = "YhEO/wu0" fullword ascii /* score: '4.00'*/
      $s134 = "mwkXe-s" fullword ascii /* score: '4.00'*/
      $s135 = "pJNQ {mB~" fullword ascii /* score: '4.00'*/
      $s136 = "S+ZwTC33l" fullword ascii /* score: '4.00'*/
      $s137 = "^o.xst" fullword ascii /* score: '4.00'*/
      $s138 = "sJmp)%^m" fullword ascii /* score: '4.00'*/
      $s139 = "PwYHMfM" fullword ascii /* score: '4.00'*/
      $s140 = "SnHnci?" fullword ascii /* score: '4.00'*/
      $s141 = "gIIae$[F?" fullword ascii /* score: '4.00'*/
      $s142 = "DcGsqCr" fullword ascii /* score: '4.00'*/
      $s143 = "The USERTRUST Network1.0," fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s144 = "pbUm>e'" fullword ascii /* score: '4.00'*/
      $s145 = ",(.DuT" fullword ascii /* score: '4.00'*/
      $s146 = "^IPVq{]b" fullword ascii /* score: '4.00'*/
      $s147 = "spxm2G/" fullword ascii /* score: '4.00'*/
      $s148 = "qL.uNR" fullword ascii /* score: '4.00'*/
      $s149 = "hruSv_XR" fullword ascii /* score: '4.00'*/
      $s150 = "(Windows XP " fullword ascii /* score: '4.00'*/
      $s151 = "UAmFqrq" fullword ascii /* score: '4.00'*/
      $s152 = "paUoCIo" fullword ascii /* score: '4.00'*/
      $s153 = " Windows " fullword ascii /* score: '4.00'*/
      $s154 = "tImT?]" fullword ascii /* score: '4.00'*/
      $s155 = "HYUL&Y@" fullword ascii /* score: '4.00'*/
      $s156 = "1bfLK@l#" fullword ascii /* score: '4.00'*/
      $s157 = "uBHK(<^K" fullword ascii /* score: '4.00'*/
      $s158 = "ICDx\\,.I" fullword ascii /* score: '4.00'*/
      $s159 = "Z4RmCcp\\f" fullword ascii /* score: '4.00'*/
      $s160 = "QFYdR0h" fullword ascii /* score: '4.00'*/
      $s161 = "wgQE/,RQVe" fullword ascii /* score: '4.00'*/
      $s162 = "'NVWml]}O" fullword ascii /* score: '4.00'*/
      $s163 = "sSOnF5(" fullword ascii /* score: '4.00'*/
      $s164 = "EuPbx>7" fullword ascii /* score: '4.00'*/
      $s165 = "hppMw1i" fullword ascii /* score: '4.00'*/
      $s166 = "'KgcHnKn" fullword ascii /* score: '4.00'*/
      $s167 = "Yamaha Stagepas 1K0" fullword ascii /* score: '4.00'*/
      $s168 = "nyFK5(6&" fullword ascii /* score: '4.00'*/
      $s169 = "zQsXz}=N" fullword ascii /* score: '4.00'*/
      $s170 = "cBXL80Wl%" fullword ascii /* score: '4.00'*/
      $s171 = "yosU?>" fullword ascii /* score: '4.00'*/
      $s172 = "NZmQq?" fullword ascii /* score: '4.00'*/
      $s173 = "QomI5Po" fullword ascii /* score: '4.00'*/
      $s174 = "cvmS\\;\"" fullword ascii /* score: '4.00'*/
      $s175 = "yqIC8^F(I" fullword ascii /* score: '4.00'*/
      $s176 = "QpcniM?" fullword ascii /* score: '4.00'*/
      $s177 = ". WPF(Windows Presentation Foundation) " fullword ascii /* score: '4.00'*/
      $s178 = "umxfupX" fullword ascii /* score: '4.00'*/
      $s179 = "hrnhB}2" fullword ascii /* score: '4.00'*/
      $s180 = "[d}.GnB" fullword ascii /* score: '4.00'*/
      $s181 = " app.config" fullword ascii /* score: '4.00'*/
      $s182 = "Yamaha Stagepas 1K" fullword ascii /* score: '4.00'*/
      $s183 = "tmtm{kS" fullword ascii /* score: '4.00'*/
      $s184 = "dNxLfm@=" fullword ascii /* score: '4.00'*/
      $s185 = "JCmu6-Xm_" fullword ascii /* score: '4.00'*/
      $s186 = "kJNI[M9" fullword ascii /* score: '4.00'*/
      $s187 = "hmED:Um" fullword ascii /* score: '4.00'*/
      $s188 = "A.Xnf|Ex" fullword ascii /* score: '4.00'*/
      $s189 = "qyrqbiQ" fullword ascii /* score: '4.00'*/
      $s190 = "RzMJcz " fullword ascii /* score: '4.00'*/
      $s191 = "aCho [4$B" fullword ascii /* score: '4.00'*/
      $s192 = "zARgJPW]" fullword ascii /* score: '4.00'*/
      $s193 = "cIrX_>e" fullword ascii /* score: '4.00'*/
      $s194 = "NpgR8&B" fullword ascii /* score: '4.00'*/
      $s195 = "4sAMm93P" fullword ascii /* score: '4.00'*/
      $s196 = "ItBvcQ," fullword ascii /* score: '4.00'*/
      $s197 = "YpemCcle!#" fullword ascii /* score: '4.00'*/
      $s198 = "~mZZg&& " fullword ascii /* score: '4.00'*/
      $s199 = "///;QQQk{{{" fullword ascii /* score: '4.00'*/
      $s200 = "PBEL\")L" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839 {
   meta:
      description = "Amadey_MALW - file ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s4 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s7 = "9':1:;:R:\\:" fullword ascii /* score: '7.00'*/
      $s8 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s9 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s10 = "vector too long" fullword ascii /* score: '6.00'*/
      $s11 = "list too long" fullword ascii /* score: '6.00'*/
      $s12 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s13 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" fullword ascii /* score: '5.00'*/
      $s14 = ".?AV?$_Func_impl_no_alloc@V?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@X$$V@std@@" fullword ascii /* score: '5.00'*/
      $s15 = "EpPoaRV1" fullword ascii /* score: '5.00'*/
      $s16 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s17 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s18 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s19 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s20 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s21 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s22 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s23 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s24 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s25 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s26 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s27 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s28 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
      $s29 = "WWWSHSh" fullword ascii /* score: '4.00'*/
      $s30 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s31 = " delete[]" fullword ascii /* score: '4.00'*/
      $s32 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s33 = "WPWWWS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s34 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s35 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s36 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" fullword ascii /* score: '4.00'*/
      $s37 = "cy@@@?$task@E@Concurrency@@U_TaskProcHandle@details@3@@details@Concurrency@@" fullword ascii /* score: '4.00'*/
      $s38 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" fullword ascii /* score: '4.00'*/
      $s39 = "323<3g3q3{3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s40 = ".?AV_ExceptionPtr_normal@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s41 = ".?AV?$_Func_impl_no_alloc@V<lambda_0456396a71e3abd88ede77bdd2823d8e>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s42 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s43 = ".?AV?$_Ref_count_obj2@U_ExceptionHolder@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s44 = ".?AV?$_Func_impl_no_alloc@V<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@E$$V@std@@" fullword ascii /* score: '4.00'*/
      $s45 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s46 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s47 = ".?AV?$_Func_impl_no_alloc@V<lambda_9de88c4009318ef1202283857f94e673>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s48 = ".?AV?$_Ref_count_obj2@U?$_Task_impl@E@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s49 = "FYY;w(|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s50 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s51 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s52 = "rrency@@" fullword ascii /* score: '4.00'*/
      $s53 = ".?AV?$_Task_async_state@X@std@@" fullword ascii /* score: '4.00'*/
      $s54 = ".?AV?$_Func_impl_no_alloc@V<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s55 = "Wj4XPV" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s56 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s57 = "YYF;w,|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s58 = ".?AV?$_Func_impl_no_alloc@V<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s59 = "Eapi-ms-win-core-fibers-l1-1-1" fullword wide /* score: '4.00'*/
      $s60 = "Eapi-ms-win-core-datetime-l1-1-1" fullword wide /* score: '4.00'*/
      $s61 = "0 0$0(0,000X0\\0`0d0h0l0p0t0x0|0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s62 = "=$=(=@=P=T=h=l=|=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s63 = "0T1X1`1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s64 = "6 6(6@6D6\\6l6p6t6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s65 = "> >$>(>,>@>D>T>X>h>l>p>x>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s66 = "4 484<4T4d4h4|4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s67 = ">)>=>^>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s68 = "L43odA0m7D2N7PGmRgtldMsX5Txi3kIsUo3sbM6cRYSaGqGje1NmZwAv9PWuBPSq" fullword ascii /* score: '4.00'*/
      $s69 = "LZTjcgJ=" fullword ascii /* score: '4.00'*/
      $s70 = "TYDdZA0eS3ii3eyteUXncxAv7ZN24k61 ZiqMNNrGEVVFrl6OT0=" fullword ascii /* score: '4.00'*/
      $s71 = "OYzjba==" fullword ascii /* score: '4.00'*/
      $s72 = "5 5(50585@5H5X5|5" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s73 = "EkSaRRmh7DJ=" fullword ascii /* score: '4.00'*/
      $s74 = "MIPgYR0k7GOe6zWqek6rLbgPTTJw2ENX6Y3o" fullword ascii /* score: '4.00'*/
      $s75 = "MXHzVu==" fullword ascii /* score: '4.00'*/
      $s76 = "G3TjOQCd5z i4eWmhAXoaxv=" fullword ascii /* score: '4.00'*/
      $s77 = "GojqZq==" fullword ascii /* score: '4.00'*/
      $s78 = "PJDpZXO 5YN=" fullword ascii /* score: '4.00'*/
      $s79 = "8ozoZAdl" fullword ascii /* score: '4.00'*/
      $s80 = "PIzoZAJ9N3Wc6POqgFc=" fullword ascii /* score: '4.00'*/
      $s81 = "8pPoZACkFAJ " fullword ascii /* score: '4.00'*/
      $s82 = "T4rjcw c5Hx=" fullword ascii /* score: '4.00'*/
      $s83 = "HFysMtVTGkdXGI==" fullword ascii /* score: '4.00'*/
      $s84 = "<5<X<~<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s85 = "8pPoZACkFAJnRPmm" fullword ascii /* score: '4.00'*/
      $s86 = "M4PUTgKS4Y0eMVqAgENlSM0j6s==" fullword ascii /* score: '4.00'*/
      $s87 = "84bVdAWn735 DPRhOVI9Mq==" fullword ascii /* score: '4.00'*/
      $s88 = "G3vmdQih5oNo" fullword ascii /* score: '4.00'*/
      $s89 = "DpLbcWyj4XylAudnLA1hbIvf" fullword ascii /* score: '4.00'*/
      $s90 = "T4VeIwdvBGKGJwqTLA1rLTzd" fullword ascii /* score: '4.00'*/
      $s91 = "P23AVzitNlW6LOqkfk1rbSUXRB q2jJs95H7QX0q6nWn6x4mflFhbS0 LTdx2D1vUZD7UWmd5Hx Jedt2ENqcm==" fullword ascii /* score: '4.00'*/
      $s92 = "ySinLM5lET1=" fullword ascii /* score: '4.00'*/
      $s93 = "PI3XZROr4HWl4u mhEM=" fullword ascii /* score: '4.00'*/
      $s94 = "SGzqcu==" fullword ascii /* score: '4.00'*/
      $s95 = "P23AVzitNlW6LOqkfk1rbSUXRB q2jJs95H7QX0q6nWn6x4mflFhbS0 LTdx2D1vUZD7VRSd6jCM3y0teAtybSshTTFA" fullword ascii /* score: '4.00'*/
      $s96 = "EXPNRPOINl zKMCGMO==" fullword ascii /* score: '4.00'*/
      $s97 = "L43ncB0SSYKHQO6m" fullword ascii /* score: '4.00'*/
      $s98 = "GZPoaQSnSHVm" fullword ascii /* score: '4.00'*/
      $s99 = "0-0H0g0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s100 = "PJDpZXO 5VSa6yKd" fullword ascii /* score: '4.00'*/
      $s101 = "DkugJcGS4X2e4V01LBw9J9TdTCRtyx==" fullword ascii /* score: '4.00'*/
      $s102 = "?8?@?\\?l?x?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s103 = "<8<@<H<P<`<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s104 = "P23AVzitNlW6LOqkfk1rbSUXRB q2jJs95H7QX0q6nWn6x4mflFhbS0 OjRvJZXgUS==" fullword ascii /* score: '4.00'*/
      $s105 = "DiUEQWdm7HWn6u6VhVtdO9we7Dxt1TFe9IfpbcdnR4Se6u6AgFBdYMVKwcWL" fullword ascii /* score: '4.00'*/
      $s106 = "UZbqbAdq7HlnRPmm" fullword ascii /* score: '4.00'*/
      $s107 = "HlurNa==" fullword ascii /* score: '4.00'*/
      $s108 = "GUUnLM5l" fullword ascii /* score: '4.00'*/
      $s109 = "HIKYZd0dRkiaFo==" fullword ascii /* score: '4.00'*/
      $s110 = "IEYUMK==" fullword ascii /* score: '4.00'*/
      $s111 = "495_5l5" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s112 = "QofeZQdBKB==" fullword ascii /* score: '4.00'*/
      $s113 = "DESgIu==" fullword ascii /* score: '4.00'*/
      $s114 = "R0a0}0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s115 = "EUVmdK==" fullword ascii /* score: '4.00'*/
      $s116 = "GUPmdK==" fullword ascii /* score: '4.00'*/
      $s117 = "T5DfZw c5Hx=" fullword ascii /* score: '4.00'*/
      $s118 = ";%<B<b<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s119 = "4.4F4X4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s120 = "5 525z5" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s121 = "LofUZA0eSX6dRPN=" fullword ascii /* score: '4.00'*/
      $s122 = "HlusMa==" fullword ascii /* score: '4.00'*/
      $s123 = "L5Pscg0m7FKU3OCl" fullword ascii /* score: '4.00'*/
      $s124 = "LXTvUVV9N3 f6ziifkM=" fullword ascii /* score: '4.00'*/
      $s125 = "6JLUcBRYEz9=" fullword ascii /* score: '4.00'*/
      $s126 = "P3fNVy0FQFOU5fOmelJvbS0X7i5tKZNXSGHpbhWq53y6NO qgENcVcghTS5dGX1LQHDJTzCOLVSyLTB=" fullword ascii /* score: '4.00'*/
      $s127 = "HVaVLdNpGT5qELRvPRc=" fullword ascii /* score: '4.00'*/
      $s128 = "MIPgYR0k7GOe6zWqek6rLbcPTTJw2ENX6Y3o" fullword ascii /* score: '4.00'*/
      $s129 = "GYPYZQST7Hmo4fGweEdbeIwvTSXw4DNw6Y8oZQV9EV0i4yZhLe==" fullword ascii /* score: '4.00'*/
      $s130 = "Q4foRA0eSX6dRPN=" fullword ascii /* score: '4.00'*/
      $s131 = ":.:?:k:{:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s132 = "64Psbg0kFAJnRyCt" fullword ascii /* score: '4.00'*/
      $s133 = "PJDpZB0b7F6a4OZ=" fullword ascii /* score: '4.00'*/
      $s134 = "6JLUcxtnEx==" fullword ascii /* score: '4.00'*/
      $s135 = "SFuqMxF=" fullword ascii /* score: '4.00'*/
      $s136 = "T5DfZw c5Hy1QUCqfAXcbws5" fullword ascii /* score: '4.00'*/
      $s137 = "9;9F9f9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s138 = "/SPPWh6yB" fullword ascii /* score: '4.00'*/
      $s139 = "P3fNVy0FQFOU5fOmelJvbS0X7i5tKZNXSGHpbhWq53y6IUdufFNSZNELSSXmNBFs7ZvVdA0qMnGmRI==" fullword ascii /* score: '4.00'*/
      $s140 = "PAUfbBZl" fullword ascii /* score: '4.00'*/
      $s141 = "HBSqVAdSRXyMROS2fkdSeG==" fullword ascii /* score: '4.00'*/
      $s142 = "84bfbABrFj6d4yB=" fullword ascii /* score: '4.00'*/
      $s143 = "L43odA0m7D2N7PGmRgt cxwp5SJi4Dds7k3YLRiV7z2f4VOuOVNqbwQrSY5lPTI=" fullword ascii /* score: '4.00'*/
      $s144 = "P3fNVy0FQFOo4fWze0pLZNLtGzBdKZNv9ofdZRS5JnGs3OSFdVFobwA2RBVqPDNs" fullword ascii /* score: '4.00'*/
      $s145 = "P23AVzitNlW6LOqkfk1rbSUXRB q2jJs95H7QX0q6nWn6x4mflFhbS0 OjRv" fullword ascii /* score: '4.00'*/
      $s146 = "HlurOK==" fullword ascii /* score: '4.00'*/
      $s147 = "P23AVzitNlW6LOqkfk1rbSUXRB q2jJs95GaTfW5J4Wr5e0vgDRdcdIm6Y0=" fullword ascii /* score: '4.00'*/
      $s148 = "DkugJcGqSX5 " fullword ascii /* score: '4.00'*/
      $s149 = "P5LbchWT6B==" fullword ascii /* score: '4.00'*/
      $s150 = "MI3ddAdqBGeeQ9==" fullword ascii /* score: '4.00'*/
      $s151 = "CMPQPQ" fullword ascii /* score: '3.50'*/
      $s152 = "system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.42'*/ /* Goodware String - occured 1577 times */
      $s153 = " delete" fullword ascii /* score: '3.00'*/
      $s154 = ";1#INF" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s155 = "9de88c4009318ef1202283857f94e673" ascii /* score: '3.00'*/
      $s156 = ".?AV?$_Func_base@E$$V@std@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s157 = ".?AV?$_CancellationTokenCallback@V<lambda_3b8ab8d2629adf61a42ee3fe177a046b>@@@details@Concurrency@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s158 = "3b8ab8d2629adf61a42ee3fe177a046b" ascii /* score: '3.00'*/
      $s159 = "7c33b2c4310ad8c6be497d7a2a561bb8" ascii /* score: '3.00'*/
      $s160 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s161 = "eb87dfd73f857f44e1a351ea42ce2b34" ascii /* score: '3.00'*/
      $s162 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s163 = "0456396a71e3abd88ede77bdd2823d8e" ascii /* score: '3.00'*/
      $s164 = "5e5ab22ea98f4361dbf159481d01f54d" ascii /* score: '3.00'*/
      $s165 = ".?AV<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s166 = "Eja-JP" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s167 = "30484@4H4P4X4`4h4p4x4" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s168 = "006700e5a2ab05704bbb0c589b88924d" ascii /* score: '3.00'*/
      $s169 = "6$6<6L6P6X6p6" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s170 = ")0U0q0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s171 = "4ba42c351ee3e4ea4a5f5ce3ae7b3915" ascii /* score: '3.00'*/
      $s172 = "K0L1\\1m1u1" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s173 = "6c55a5f34bb433fbd933a168577b1838" ascii /* score: '3.00'*/
      $s174 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s175 = ">$>(>8><>@>H>`>d>|>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s176 = ":$:(:,:4:L:\\:`:h:" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s177 = "0 0$0|0" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s178 = "9V9h9v9" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s179 = "D8(Ht'" fullword ascii /* score: '1.00'*/
      $s180 = " new[]" fullword ascii /* score: '1.00'*/
      $s181 = "u kE$<" fullword ascii /* score: '1.00'*/
      $s182 = ":u\"f9z" fullword ascii /* score: '1.00'*/
      $s183 = "UTF-16LEUNICODE" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s184 = "CM @PRj" fullword ascii /* score: '1.00'*/
      $s185 = "<=upG8" fullword ascii /* score: '1.00'*/
      $s186 = "zSSSSj" fullword ascii /* score: '1.00'*/
      $s187 = "<at.<rt!<wt" fullword ascii /* score: '1.00'*/
      $s188 = "api-ms-" fullword wide /* score: '1.00'*/
      $s189 = "ext-ms-" fullword wide /* score: '1.00'*/
      $s190 = "2G2Q2[2r2|2" fullword ascii /* score: '1.00'*/
      $s191 = "8G8Q8[8r8|8" fullword ascii /* score: '1.00'*/
      $s192 = "Sk{$4kK(4" fullword ascii /* score: '1.00'*/
      $s193 = "6G6Q6[6r6|6" fullword ascii /* score: '1.00'*/
      $s194 = ":2:<:g:q:{:" fullword ascii /* score: '1.00'*/
      $s195 = "7'818;8R8\\8" fullword ascii /* score: '1.00'*/
      $s196 = ".?AV_DefaultPPLTaskScheduler@details@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s197 = "20242`7d7h7l7p7t7x7|7" fullword ascii /* score: '1.00'*/
      $s198 = "=2=<=g=q={=" fullword ascii /* score: '1.00'*/
      $s199 = ">2><>g>q>{>" fullword ascii /* score: '1.00'*/
      $s200 = ";{dv(2" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d {
   meta:
      description = "Amadey_MALW - file 7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d"
   strings:
      $s1 = "?GetProcessWindowStation" fullword ascii /* score: '20.00'*/
      $s2 = "C:\\halewupesi_xafidehusef\\57\\molaj\\yawavilunu-48\\goyu.pdb" fullword ascii /* score: '20.00'*/
      $s3 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s4 = "vuvugojonofisajihepucejekexuzewoyicuweweyevucaceyu" fullword ascii /* score: '9.00'*/
      $s5 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s6 = ".Yosumaxezepuh bacoseyeyen wobil wutuxuhocinicu" fullword wide /* score: '9.00'*/
      $s7 = "hozasilor" fullword wide /* score: '8.00'*/
      $s8 = "foxacirizip" fullword wide /* score: '8.00'*/
      $s9 = "jewuwomekorecokoyujesac" fullword wide /* score: '8.00'*/
      $s10 = "pazefovatasodobuzuhoxutirivejehi" fullword wide /* score: '8.00'*/
      $s11 = "jijozumadik" fullword wide /* score: '8.00'*/
      $s12 = "Puzahirubehubin1Duconobajaz mexafa pigoyu xojedeluxop ruy tetokuz" fullword wide /* score: '7.00'*/
      $s13 = "FilesVersion" fullword wide /* score: '7.00'*/
      $s14 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s15 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s16 = "pohuyis sofog lesamuwaliy" fullword wide /* score: '6.00'*/
      $s17 = "ilufen foficoju wixoli" fullword wide /* score: '6.00'*/
      $s18 = "25.55.47.80" fullword wide /* score: '6.00'*/
      $s19 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s20 = "\"sQ -;" fullword ascii /* score: '5.00'*/
      $s21 = "FHohuji jafiri posumowa masugi sogicijizu gunuyobo kavewab xeyevexubixuCHubupoduyixama kijozusahesi bosifuhukusum vinoy pediw mi" wide /* score: '5.00'*/
      $s22 = " delete[]" fullword ascii /* score: '4.00'*/
      $s23 = "uoFB~r+0" fullword ascii /* score: '4.00'*/
      $s24 = "rfHu)T*" fullword ascii /* score: '4.00'*/
      $s25 = "xKsy4%'-*" fullword ascii /* score: '4.00'*/
      $s26 = "g%T.VDt" fullword ascii /* score: '4.00'*/
      $s27 = "cXOX\\Z" fullword ascii /* score: '4.00'*/
      $s28 = "kzYa)\\}RY" fullword ascii /* score: '4.00'*/
      $s29 = "LhyT/VT" fullword ascii /* score: '4.00'*/
      $s30 = "RZirYIj=n" fullword ascii /* score: '4.00'*/
      $s31 = "GwWDTH!DwY" fullword ascii /* score: '4.00'*/
      $s32 = "lylC-QYE" fullword ascii /* score: '4.00'*/
      $s33 = "'ugmV!cm" fullword ascii /* score: '4.00'*/
      $s34 = "~:jHVn\\Wm" fullword ascii /* score: '4.00'*/
      $s35 = "fDmf}C)" fullword ascii /* score: '4.00'*/
      $s36 = "uJsJ\"x" fullword ascii /* score: '4.00'*/
      $s37 = "AjFSe H" fullword ascii /* score: '4.00'*/
      $s38 = "vfkmdoz," fullword ascii /* score: '4.00'*/
      $s39 = "bDRVT|0J&" fullword ascii /* score: '4.00'*/
      $s40 = "MFdp'Ii" fullword ascii /* score: '4.00'*/
      $s41 = "Oxfyfi-" fullword ascii /* score: '4.00'*/
      $s42 = "cagapizagesi" fullword wide /* score: '4.00'*/
      $s43 = "KJuf sub lojuruvono wuhoyekuwuw ruyami yakotujusifaru voxekuvecopig lunezovo" fullword wide /* score: '4.00'*/
      $s44 = "7Jobat jusomekaru yaledijip dujekaberozogo kadabefutabek" fullword wide /* score: '4.00'*/
      $s45 = "Bikazoyo vatuwefeyopuyaw siwa" fullword wide /* score: '4.00'*/
      $s46 = "Hola arifmeco soft" fullword wide /* score: '4.00'*/
      $s47 = " delete" fullword ascii /* score: '3.00'*/
      $s48 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s49 = "\\=R`v^" fullword ascii /* score: '2.00'*/
      $s50 = "\\ktKd`" fullword ascii /* score: '2.00'*/
      $s51 = "\\kiB,?DF" fullword ascii /* score: '2.00'*/
      $s52 = "WxwY29" fullword ascii /* score: '2.00'*/
      $s53 = "\\pgrZ>" fullword ascii /* score: '2.00'*/
      $s54 = "uWkJM7" fullword ascii /* score: '2.00'*/
      $s55 = " new[]" fullword ascii /* score: '1.00'*/
      $s56 = ":T//oA" fullword ascii /* score: '1.00'*/
      $s57 = ")h-t/C" fullword ascii /* score: '1.00'*/
      $s58 = "8^1t{.BN" fullword ascii /* score: '1.00'*/
      $s59 = "609[wB" fullword ascii /* score: '1.00'*/
      $s60 = "ncS\\u2" fullword ascii /* score: '1.00'*/
      $s61 = "o$s_f#" fullword ascii /* score: '1.00'*/
      $s62 = "{SB`L[" fullword ascii /* score: '1.00'*/
      $s63 = "!fI*~?kU" fullword ascii /* score: '1.00'*/
      $s64 = "}(D Uh" fullword ascii /* score: '1.00'*/
      $s65 = "A%S3*8Rv" fullword ascii /* score: '1.00'*/
      $s66 = ":=@{ z" fullword ascii /* score: '1.00'*/
      $s67 = "l&KWSJ" fullword ascii /* score: '1.00'*/
      $s68 = "\"I+OW3P" fullword ascii /* score: '1.00'*/
      $s69 = "gKTF~R" fullword ascii /* score: '1.00'*/
      $s70 = ">bG<\"=" fullword ascii /* score: '1.00'*/
      $s71 = "9!O#)y~" fullword ascii /* score: '1.00'*/
      $s72 = "d##,;)" fullword ascii /* score: '1.00'*/
      $s73 = "^%iW)nZ" fullword ascii /* score: '1.00'*/
      $s74 = "@~.^iuW" fullword ascii /* score: '1.00'*/
      $s75 = "2#s5G-\"" fullword ascii /* score: '1.00'*/
      $s76 = "9xw:4?" fullword ascii /* score: '1.00'*/
      $s77 = "62byL8" fullword ascii /* score: '1.00'*/
      $s78 = "Vm6lU`" fullword ascii /* score: '1.00'*/
      $s79 = "auc[w>8bZJ" fullword ascii /* score: '1.00'*/
      $s80 = ">`O#aY" fullword ascii /* score: '1.00'*/
      $s81 = "U[]T`B" fullword ascii /* score: '1.00'*/
      $s82 = ">L@F3{L" fullword ascii /* score: '1.00'*/
      $s83 = "{]g)N;u" fullword ascii /* score: '1.00'*/
      $s84 = "2_Gz!k" fullword ascii /* score: '1.00'*/
      $s85 = "EZ2:/z" fullword ascii /* score: '1.00'*/
      $s86 = "y+L,W>/" fullword ascii /* score: '1.00'*/
      $s87 = "8QW[R.f" fullword ascii /* score: '1.00'*/
      $s88 = "x:4hOCJ{" fullword ascii /* score: '1.00'*/
      $s89 = "~'o@V|" fullword ascii /* score: '1.00'*/
      $s90 = "b'VP5S" fullword ascii /* score: '1.00'*/
      $s91 = "#24C?Q" fullword ascii /* score: '1.00'*/
      $s92 = "Cp3j.a@" fullword ascii /* score: '1.00'*/
      $s93 = "{]!j9@z" fullword ascii /* score: '1.00'*/
      $s94 = "]iG6RPK*>,P" fullword ascii /* score: '1.00'*/
      $s95 = "Tx[wQX[" fullword ascii /* score: '1.00'*/
      $s96 = "(NG$i\"" fullword ascii /* score: '1.00'*/
      $s97 = "3TQeeS" fullword ascii /* score: '1.00'*/
      $s98 = "CxQnpq" fullword ascii /* score: '1.00'*/
      $s99 = "|[yQK(" fullword ascii /* score: '1.00'*/
      $s100 = "sz)&$o" fullword ascii /* score: '1.00'*/
      $s101 = "YYh$)@" fullword ascii /* score: '1.00'*/
      $s102 = "*\"YY0?" fullword ascii /* score: '1.00'*/
      $s103 = "Jo7Fl$`cH" fullword ascii /* score: '1.00'*/
      $s104 = ")o7&H+s" fullword ascii /* score: '1.00'*/
      $s105 = "$tPS40" fullword ascii /* score: '1.00'*/
      $s106 = "^g][0O" fullword ascii /* score: '1.00'*/
      $s107 = "B{=Ug9,." fullword ascii /* score: '1.00'*/
      $s108 = "'@kx}/1" fullword ascii /* score: '1.00'*/
      $s109 = "xwY#8}" fullword ascii /* score: '1.00'*/
      $s110 = "lU%Fz9P" fullword ascii /* score: '1.00'*/
      $s111 = "k!rY,|Z" fullword ascii /* score: '1.00'*/
      $s112 = "}-bGU4" fullword ascii /* score: '1.00'*/
      $s113 = "q02l? P" fullword ascii /* score: '1.00'*/
      $s114 = "!diTdv" fullword ascii /* score: '1.00'*/
      $s115 = "ler`73f" fullword ascii /* score: '1.00'*/
      $s116 = "!CqK$E" fullword ascii /* score: '1.00'*/
      $s117 = "Ouf~nl" fullword ascii /* score: '1.00'*/
      $s118 = "qDv=iW" fullword ascii /* score: '1.00'*/
      $s119 = "[@B^~;Ka`:" fullword ascii /* score: '1.00'*/
      $s120 = "Z%M8-." fullword ascii /* score: '1.00'*/
      $s121 = "C3d._%\"" fullword ascii /* score: '1.00'*/
      $s122 = "^S?HVt8" fullword ascii /* score: '1.00'*/
      $s123 = "4g\\KYC" fullword ascii /* score: '1.00'*/
      $s124 = "3-dSbS^A" fullword ascii /* score: '1.00'*/
      $s125 = "Fh;#[/" fullword ascii /* score: '1.00'*/
      $s126 = "/\\&_`(q" fullword ascii /* score: '1.00'*/
      $s127 = "w?lT\"*q" fullword ascii /* score: '1.00'*/
      $s128 = "QMs&DTy" fullword ascii /* score: '1.00'*/
      $s129 = "2{X\"I=" fullword ascii /* score: '1.00'*/
      $s130 = "OoTK]u" fullword ascii /* score: '1.00'*/
      $s131 = "1_\"uKG" fullword ascii /* score: '1.00'*/
      $s132 = "<@T5w," fullword ascii /* score: '1.00'*/
      $s133 = "8/Z{Qt" fullword ascii /* score: '1.00'*/
      $s134 = "ppC4l_[" fullword ascii /* score: '1.00'*/
      $s135 = "3\"v=e{" fullword ascii /* score: '1.00'*/
      $s136 = "!X}Mt$$sl3" fullword ascii /* score: '1.00'*/
      $s137 = "r3DUyp&5" fullword ascii /* score: '1.00'*/
      $s138 = ";PAz(g" fullword ascii /* score: '1.00'*/
      $s139 = "Q|qqah" fullword ascii /* score: '1.00'*/
      $s140 = "n5^K{9" fullword ascii /* score: '1.00'*/
      $s141 = "baWp$p" fullword ascii /* score: '1.00'*/
      $s142 = "*W_-d-" fullword ascii /* score: '1.00'*/
      $s143 = "fm?i<4" fullword ascii /* score: '1.00'*/
      $s144 = "w)ZgHv" fullword ascii /* score: '1.00'*/
      $s145 = "}ra!l+" fullword ascii /* score: '1.00'*/
      $s146 = "JBF}(O2" fullword ascii /* score: '1.00'*/
      $s147 = "dj>_`[" fullword ascii /* score: '1.00'*/
      $s148 = "BW}~]1" fullword ascii /* score: '1.00'*/
      $s149 = "Jc|(By" fullword ascii /* score: '1.00'*/
      $s150 = "QV(6&Ik" fullword ascii /* score: '1.00'*/
      $s151 = "%+o@;{" fullword ascii /* score: '1.00'*/
      $s152 = "mCQVAv" fullword ascii /* score: '1.00'*/
      $s153 = "VK:^5S" fullword ascii /* score: '1.00'*/
      $s154 = "PinL]o" fullword ascii /* score: '1.00'*/
      $s155 = "6v70W@" fullword ascii /* score: '1.00'*/
      $s156 = "}&f' c" fullword ascii /* score: '1.00'*/
      $s157 = "56l6|t" fullword ascii /* score: '1.00'*/
      $s158 = "zPt|Iu" fullword ascii /* score: '1.00'*/
      $s159 = "_N}MT}" fullword ascii /* score: '1.00'*/
      $s160 = "DK!K^&G" fullword ascii /* score: '1.00'*/
      $s161 = "#e}r9ia" fullword ascii /* score: '1.00'*/
      $s162 = ":xC(S0" fullword ascii /* score: '1.00'*/
      $s163 = "P{^N^#" fullword ascii /* score: '1.00'*/
      $s164 = "wB0)p." fullword ascii /* score: '1.00'*/
      $s165 = "=]I,B}" fullword ascii /* score: '1.00'*/
      $s166 = "IxD9STWV" fullword ascii /* score: '1.00'*/
      $s167 = ".naEoO" fullword ascii /* score: '1.00'*/
      $s168 = "^K&u,}~" fullword ascii /* score: '1.00'*/
      $s169 = "F%i+UK" fullword ascii /* score: '1.00'*/
      $s170 = "dV3rFM" fullword ascii /* score: '1.00'*/
      $s171 = "%Rf~>?XJ" fullword ascii /* score: '1.00'*/
      $s172 = "P'*'j _@" fullword ascii /* score: '1.00'*/
      $s173 = ">TtJ}o" fullword ascii /* score: '1.00'*/
      $s174 = "%kYVbv" fullword ascii /* score: '1.00'*/
      $s175 = "wN SMq" fullword ascii /* score: '1.00'*/
      $s176 = "({qh.1" fullword ascii /* score: '1.00'*/
      $s177 = "O4\"s&$-P" fullword ascii /* score: '1.00'*/
      $s178 = "$py2>j" fullword ascii /* score: '1.00'*/
      $s179 = "8Mm&Buh" fullword ascii /* score: '1.00'*/
      $s180 = "? 98e<Q" fullword ascii /* score: '1.00'*/
      $s181 = "WEy83#CtJ" fullword ascii /* score: '1.00'*/
      $s182 = "}/\\hdZ" fullword ascii /* score: '1.00'*/
      $s183 = "9)?ysT" fullword ascii /* score: '1.00'*/
      $s184 = "@pR^o?%" fullword ascii /* score: '1.00'*/
      $s185 = "Vy~r%r" fullword ascii /* score: '1.00'*/
      $s186 = "+Pz!g1" fullword ascii /* score: '1.00'*/
      $s187 = "2j<TB7" fullword ascii /* score: '1.00'*/
      $s188 = "`t;IDB~a4" fullword ascii /* score: '1.00'*/
      $s189 = "O2Te-u" fullword ascii /* score: '1.00'*/
      $s190 = "tr>![]" fullword ascii /* score: '1.00'*/
      $s191 = "j~f.]8" fullword ascii /* score: '1.00'*/
      $s192 = "j1^w)mx" fullword ascii /* score: '1.00'*/
      $s193 = "uSO\"'Qh" fullword ascii /* score: '1.00'*/
      $s194 = "wN|3{Q" fullword ascii /* score: '1.00'*/
      $s195 = "IgF#Mzb" fullword ascii /* score: '1.00'*/
      $s196 = "4#]Lq*5" fullword ascii /* score: '1.00'*/
      $s197 = "?4rIB&" fullword ascii /* score: '1.00'*/
      $s198 = "6^j>J%" fullword ascii /* score: '1.00'*/
      $s199 = "Hkmqg-" fullword ascii /* score: '1.00'*/
      $s200 = "3'{8jkI" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197 {
   meta:
      description = "Amadey_MALW - file 8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197"
   strings:
      $s1 = "?GetProcessWindowStation" fullword ascii /* score: '20.00'*/
      $s2 = "C:\\halewupesi_xafidehusef\\57\\molaj\\yawavilunu-48\\goyu.pdb" fullword ascii /* score: '20.00'*/
      $s3 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s4 = "vuvugojonofisajihepucejekexuzewoyicuweweyevucaceyu" fullword ascii /* score: '9.00'*/
      $s5 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s6 = ".Yosumaxezepuh bacoseyeyen wobil wutuxuhocinicu" fullword wide /* score: '9.00'*/
      $s7 = "hozasilor" fullword wide /* score: '8.00'*/
      $s8 = "foxacirizip" fullword wide /* score: '8.00'*/
      $s9 = "jewuwomekorecokoyujesac" fullword wide /* score: '8.00'*/
      $s10 = "pazefovatasodobuzuhoxutirivejehi" fullword wide /* score: '8.00'*/
      $s11 = "jijozumadik" fullword wide /* score: '8.00'*/
      $s12 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae" ascii /* score: '8.00'*/
      $s13 = "Puzahirubehubin1Duconobajaz mexafa pigoyu xojedeluxop ruy tetokuz" fullword wide /* score: '7.00'*/
      $s14 = "FilesVersion" fullword wide /* score: '7.00'*/
      $s15 = "<yyyyyyyyyyyyyy" fullword ascii /* score: '7.00'*/
      $s16 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s17 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s18 = "pohuyis sofog lesamuwaliy" fullword wide /* score: '6.00'*/
      $s19 = "ilufen foficoju wixoli" fullword wide /* score: '6.00'*/
      $s20 = "25.55.47.80" fullword wide /* score: '6.00'*/
      $s21 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s22 = "\"sQ -;" fullword ascii /* score: '5.00'*/
      $s23 = "FHohuji jafiri posumowa masugi sogicijizu gunuyobo kavewab xeyevexubixuCHubupoduyixama kijozusahesi bosifuhukusum vinoy pediw mi" wide /* score: '5.00'*/
      $s24 = " delete[]" fullword ascii /* score: '4.00'*/
      $s25 = "uoFB~r+0" fullword ascii /* score: '4.00'*/
      $s26 = "rfHu)T*" fullword ascii /* score: '4.00'*/
      $s27 = "xKsy4%'-*" fullword ascii /* score: '4.00'*/
      $s28 = "g%T.VDt" fullword ascii /* score: '4.00'*/
      $s29 = "cXOX\\Z" fullword ascii /* score: '4.00'*/
      $s30 = "kzYa)\\}RY" fullword ascii /* score: '4.00'*/
      $s31 = "LhyT/VT" fullword ascii /* score: '4.00'*/
      $s32 = "RZirYIj=n" fullword ascii /* score: '4.00'*/
      $s33 = "GwWDTH!DwY" fullword ascii /* score: '4.00'*/
      $s34 = "lylC-QYE" fullword ascii /* score: '4.00'*/
      $s35 = "'ugmV!cm" fullword ascii /* score: '4.00'*/
      $s36 = "~:jHVn\\Wm" fullword ascii /* score: '4.00'*/
      $s37 = "fDmf}C)" fullword ascii /* score: '4.00'*/
      $s38 = "uJsJ\"x" fullword ascii /* score: '4.00'*/
      $s39 = "AjFSe H" fullword ascii /* score: '4.00'*/
      $s40 = "vfkmdoz," fullword ascii /* score: '4.00'*/
      $s41 = "bDRVT|0J&" fullword ascii /* score: '4.00'*/
      $s42 = "MFdp'Ii" fullword ascii /* score: '4.00'*/
      $s43 = "Oxfyfi-" fullword ascii /* score: '4.00'*/
      $s44 = "cagapizagesi" fullword wide /* score: '4.00'*/
      $s45 = "KJuf sub lojuruvono wuhoyekuwuw ruyami yakotujusifaru voxekuvecopig lunezovo" fullword wide /* score: '4.00'*/
      $s46 = "7Jobat jusomekaru yaledijip dujekaberozogo kadabefutabek" fullword wide /* score: '4.00'*/
      $s47 = "Bikazoyo vatuwefeyopuyaw siwa" fullword wide /* score: '4.00'*/
      $s48 = "Hola arifmeco soft" fullword wide /* score: '4.00'*/
      $s49 = "iiiiiii///" fullword ascii /* score: '4.00'*/
      $s50 = "//D0mmmmmmmmmmmmmmmm" fullword ascii /* score: '4.00'*/
      $s51 = ".F.zzZ" fullword ascii /* score: '4.00'*/
      $s52 = "z2)zdddddFFF" fullword ascii /* score: '4.00'*/
      $s53 = " delete" fullword ascii /* score: '3.00'*/
      $s54 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s55 = "......2" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s56 = "WWW]]]" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s57 = "\\=R`v^" fullword ascii /* score: '2.00'*/
      $s58 = "\\ktKd`" fullword ascii /* score: '2.00'*/
      $s59 = "\\kiB,?DF" fullword ascii /* score: '2.00'*/
      $s60 = "WxwY29" fullword ascii /* score: '2.00'*/
      $s61 = "\\pgrZ>" fullword ascii /* score: '2.00'*/
      $s62 = "uWkJM7" fullword ascii /* score: '2.00'*/
      $s63 = " new[]" fullword ascii /* score: '1.00'*/
      $s64 = ":T//oA" fullword ascii /* score: '1.00'*/
      $s65 = ")h-t/C" fullword ascii /* score: '1.00'*/
      $s66 = "8^1t{.BN" fullword ascii /* score: '1.00'*/
      $s67 = "609[wB" fullword ascii /* score: '1.00'*/
      $s68 = "ncS\\u2" fullword ascii /* score: '1.00'*/
      $s69 = "o$s_f#" fullword ascii /* score: '1.00'*/
      $s70 = "{SB`L[" fullword ascii /* score: '1.00'*/
      $s71 = "!fI*~?kU" fullword ascii /* score: '1.00'*/
      $s72 = "}(D Uh" fullword ascii /* score: '1.00'*/
      $s73 = "A%S3*8Rv" fullword ascii /* score: '1.00'*/
      $s74 = ":=@{ z" fullword ascii /* score: '1.00'*/
      $s75 = "l&KWSJ" fullword ascii /* score: '1.00'*/
      $s76 = "\"I+OW3P" fullword ascii /* score: '1.00'*/
      $s77 = "gKTF~R" fullword ascii /* score: '1.00'*/
      $s78 = ">bG<\"=" fullword ascii /* score: '1.00'*/
      $s79 = "9!O#)y~" fullword ascii /* score: '1.00'*/
      $s80 = "d##,;)" fullword ascii /* score: '1.00'*/
      $s81 = "^%iW)nZ" fullword ascii /* score: '1.00'*/
      $s82 = "@~.^iuW" fullword ascii /* score: '1.00'*/
      $s83 = "2#s5G-\"" fullword ascii /* score: '1.00'*/
      $s84 = "9xw:4?" fullword ascii /* score: '1.00'*/
      $s85 = "62byL8" fullword ascii /* score: '1.00'*/
      $s86 = "Vm6lU`" fullword ascii /* score: '1.00'*/
      $s87 = "auc[w>8bZJ" fullword ascii /* score: '1.00'*/
      $s88 = ">`O#aY" fullword ascii /* score: '1.00'*/
      $s89 = "U[]T`B" fullword ascii /* score: '1.00'*/
      $s90 = ">L@F3{L" fullword ascii /* score: '1.00'*/
      $s91 = "{]g)N;u" fullword ascii /* score: '1.00'*/
      $s92 = "2_Gz!k" fullword ascii /* score: '1.00'*/
      $s93 = "EZ2:/z" fullword ascii /* score: '1.00'*/
      $s94 = "y+L,W>/" fullword ascii /* score: '1.00'*/
      $s95 = "8QW[R.f" fullword ascii /* score: '1.00'*/
      $s96 = "x:4hOCJ{" fullword ascii /* score: '1.00'*/
      $s97 = "~'o@V|" fullword ascii /* score: '1.00'*/
      $s98 = "b'VP5S" fullword ascii /* score: '1.00'*/
      $s99 = "#24C?Q" fullword ascii /* score: '1.00'*/
      $s100 = "Cp3j.a@" fullword ascii /* score: '1.00'*/
      $s101 = "{]!j9@z" fullword ascii /* score: '1.00'*/
      $s102 = "]iG6RPK*>,P" fullword ascii /* score: '1.00'*/
      $s103 = "Tx[wQX[" fullword ascii /* score: '1.00'*/
      $s104 = "(NG$i\"" fullword ascii /* score: '1.00'*/
      $s105 = "3TQeeS" fullword ascii /* score: '1.00'*/
      $s106 = "CxQnpq" fullword ascii /* score: '1.00'*/
      $s107 = "|[yQK(" fullword ascii /* score: '1.00'*/
      $s108 = "sz)&$o" fullword ascii /* score: '1.00'*/
      $s109 = "YYh$)@" fullword ascii /* score: '1.00'*/
      $s110 = "*\"YY0?" fullword ascii /* score: '1.00'*/
      $s111 = "Jo7Fl$`cH" fullword ascii /* score: '1.00'*/
      $s112 = ")o7&H+s" fullword ascii /* score: '1.00'*/
      $s113 = "$tPS40" fullword ascii /* score: '1.00'*/
      $s114 = "^g][0O" fullword ascii /* score: '1.00'*/
      $s115 = "B{=Ug9,." fullword ascii /* score: '1.00'*/
      $s116 = "'@kx}/1" fullword ascii /* score: '1.00'*/
      $s117 = "xwY#8}" fullword ascii /* score: '1.00'*/
      $s118 = "lU%Fz9P" fullword ascii /* score: '1.00'*/
      $s119 = "k!rY,|Z" fullword ascii /* score: '1.00'*/
      $s120 = "}-bGU4" fullword ascii /* score: '1.00'*/
      $s121 = "q02l? P" fullword ascii /* score: '1.00'*/
      $s122 = "!diTdv" fullword ascii /* score: '1.00'*/
      $s123 = "ler`73f" fullword ascii /* score: '1.00'*/
      $s124 = "!CqK$E" fullword ascii /* score: '1.00'*/
      $s125 = "Ouf~nl" fullword ascii /* score: '1.00'*/
      $s126 = "qDv=iW" fullword ascii /* score: '1.00'*/
      $s127 = "[@B^~;Ka`:" fullword ascii /* score: '1.00'*/
      $s128 = "Z%M8-." fullword ascii /* score: '1.00'*/
      $s129 = "C3d._%\"" fullword ascii /* score: '1.00'*/
      $s130 = "^S?HVt8" fullword ascii /* score: '1.00'*/
      $s131 = "4g\\KYC" fullword ascii /* score: '1.00'*/
      $s132 = "3-dSbS^A" fullword ascii /* score: '1.00'*/
      $s133 = "Fh;#[/" fullword ascii /* score: '1.00'*/
      $s134 = "/\\&_`(q" fullword ascii /* score: '1.00'*/
      $s135 = "w?lT\"*q" fullword ascii /* score: '1.00'*/
      $s136 = "QMs&DTy" fullword ascii /* score: '1.00'*/
      $s137 = "2{X\"I=" fullword ascii /* score: '1.00'*/
      $s138 = "OoTK]u" fullword ascii /* score: '1.00'*/
      $s139 = "1_\"uKG" fullword ascii /* score: '1.00'*/
      $s140 = "<@T5w," fullword ascii /* score: '1.00'*/
      $s141 = "8/Z{Qt" fullword ascii /* score: '1.00'*/
      $s142 = "ppC4l_[" fullword ascii /* score: '1.00'*/
      $s143 = "3\"v=e{" fullword ascii /* score: '1.00'*/
      $s144 = "!X}Mt$$sl3" fullword ascii /* score: '1.00'*/
      $s145 = "r3DUyp&5" fullword ascii /* score: '1.00'*/
      $s146 = ";PAz(g" fullword ascii /* score: '1.00'*/
      $s147 = "Q|qqah" fullword ascii /* score: '1.00'*/
      $s148 = "n5^K{9" fullword ascii /* score: '1.00'*/
      $s149 = "baWp$p" fullword ascii /* score: '1.00'*/
      $s150 = "*W_-d-" fullword ascii /* score: '1.00'*/
      $s151 = "fm?i<4" fullword ascii /* score: '1.00'*/
      $s152 = "w)ZgHv" fullword ascii /* score: '1.00'*/
      $s153 = "}ra!l+" fullword ascii /* score: '1.00'*/
      $s154 = "JBF}(O2" fullword ascii /* score: '1.00'*/
      $s155 = "dj>_`[" fullword ascii /* score: '1.00'*/
      $s156 = "BW}~]1" fullword ascii /* score: '1.00'*/
      $s157 = "Jc|(By" fullword ascii /* score: '1.00'*/
      $s158 = "QV(6&Ik" fullword ascii /* score: '1.00'*/
      $s159 = "%+o@;{" fullword ascii /* score: '1.00'*/
      $s160 = "mCQVAv" fullword ascii /* score: '1.00'*/
      $s161 = "VK:^5S" fullword ascii /* score: '1.00'*/
      $s162 = "PinL]o" fullword ascii /* score: '1.00'*/
      $s163 = "6v70W@" fullword ascii /* score: '1.00'*/
      $s164 = "}&f' c" fullword ascii /* score: '1.00'*/
      $s165 = "56l6|t" fullword ascii /* score: '1.00'*/
      $s166 = "zPt|Iu" fullword ascii /* score: '1.00'*/
      $s167 = "_N}MT}" fullword ascii /* score: '1.00'*/
      $s168 = "DK!K^&G" fullword ascii /* score: '1.00'*/
      $s169 = "#e}r9ia" fullword ascii /* score: '1.00'*/
      $s170 = ":xC(S0" fullword ascii /* score: '1.00'*/
      $s171 = "P{^N^#" fullword ascii /* score: '1.00'*/
      $s172 = "wB0)p." fullword ascii /* score: '1.00'*/
      $s173 = "=]I,B}" fullword ascii /* score: '1.00'*/
      $s174 = "IxD9STWV" fullword ascii /* score: '1.00'*/
      $s175 = ".naEoO" fullword ascii /* score: '1.00'*/
      $s176 = "^K&u,}~" fullword ascii /* score: '1.00'*/
      $s177 = "F%i+UK" fullword ascii /* score: '1.00'*/
      $s178 = "dV3rFM" fullword ascii /* score: '1.00'*/
      $s179 = "%Rf~>?XJ" fullword ascii /* score: '1.00'*/
      $s180 = "P'*'j _@" fullword ascii /* score: '1.00'*/
      $s181 = ">TtJ}o" fullword ascii /* score: '1.00'*/
      $s182 = "%kYVbv" fullword ascii /* score: '1.00'*/
      $s183 = "wN SMq" fullword ascii /* score: '1.00'*/
      $s184 = "({qh.1" fullword ascii /* score: '1.00'*/
      $s185 = "O4\"s&$-P" fullword ascii /* score: '1.00'*/
      $s186 = "$py2>j" fullword ascii /* score: '1.00'*/
      $s187 = "8Mm&Buh" fullword ascii /* score: '1.00'*/
      $s188 = "? 98e<Q" fullword ascii /* score: '1.00'*/
      $s189 = "WEy83#CtJ" fullword ascii /* score: '1.00'*/
      $s190 = "}/\\hdZ" fullword ascii /* score: '1.00'*/
      $s191 = "9)?ysT" fullword ascii /* score: '1.00'*/
      $s192 = "@pR^o?%" fullword ascii /* score: '1.00'*/
      $s193 = "Vy~r%r" fullword ascii /* score: '1.00'*/
      $s194 = "+Pz!g1" fullword ascii /* score: '1.00'*/
      $s195 = "2j<TB7" fullword ascii /* score: '1.00'*/
      $s196 = "`t;IDB~a4" fullword ascii /* score: '1.00'*/
      $s197 = "O2Te-u" fullword ascii /* score: '1.00'*/
      $s198 = "tr>![]" fullword ascii /* score: '1.00'*/
      $s199 = "j~f.]8" fullword ascii /* score: '1.00'*/
      $s200 = "j1^w)mx" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_6b89cdfe0d3ebc90994ee564aac9c88b0df80f25720aedadff660a0d079ad0c9 {
   meta:
      description = "Amadey_MALW - file 6b89cdfe0d3ebc90994ee564aac9c88b0df80f25720aedadff660a0d079ad0c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "6b89cdfe0d3ebc90994ee564aac9c88b0df80f25720aedadff660a0d079ad0c9"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '32.00'*/
      $s2 = "?CheckAndExecuteCommand@@YAHGPAVCCmdTarget@@@Z" fullword ascii /* score: '26.00'*/
      $s3 = "TraceLog-4-0.dll" fullword ascii /* score: '25.00'*/
      $s4 = "-- IMallocSpy HEADSIGNATURE Corrupted! - 0x%08x, ID=%08lu, %lu bytes" fullword wide /* score: '24.00'*/
      $s5 = "cplib.dll" fullword ascii /* score: '23.00'*/
      $s6 = "uitools.dll" fullword ascii /* score: '23.00'*/
      $s7 = "cube.dll" fullword ascii /* score: '23.00'*/
      $s8 = "cnxsrv.dll" fullword ascii /* score: '23.00'*/
      $s9 = "cpqry.dll" fullword ascii /* score: '23.00'*/
      $s10 = "kagtux.dll" fullword ascii /* score: '23.00'*/
      $s11 = "krptdlg.dll" fullword ascii /* score: '23.00'*/
      $s12 = "BOFCEngine.dll" fullword ascii /* score: '23.00'*/
      $s13 = "boprompteditor.dll" fullword ascii /* score: '23.00'*/
      $s14 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s15 = "pdflib.dll" fullword ascii /* score: '23.00'*/
      $s16 = "rptdisp.dll" fullword ascii /* score: '23.00'*/
      $s17 = "kquery.dll" fullword ascii /* score: '23.00'*/
      $s18 = "boDeploy.dll" fullword ascii /* score: '23.00'*/
      $s19 = "ksqldg.dll" fullword ascii /* score: '23.00'*/
      $s20 = "desengine.dll" fullword ascii /* score: '23.00'*/
      $s21 = "boezlib.dll" fullword ascii /* score: '23.00'*/
      $s22 = "vartools.dll" fullword ascii /* score: '23.00'*/
      $s23 = "bofcui.dll" fullword ascii /* score: '23.00'*/
      $s24 = "%Error in Login Credentials" fullword wide /* score: '23.00'*/
      $s25 = "wqapbo.dll" fullword wide /* score: '23.00'*/
      $s26 = "Pkernel32.dll" fullword wide /* score: '23.00'*/
      $s27 = "designer.exe" fullword ascii /* score: '22.00'*/
      $s28 = "-- IMallocSpy PostRealloc - 0x%08x, ID=%08lu, %lu bytes" fullword wide /* score: '22.00'*/
      $s29 = "?DoCSExecute@BOCSHelper@@SA?AW4Status@ConnectionServer@@PAVjob_thread@@AAV?$ibo_ptr@UJobResultSet@ConnectionServer@@@@AAV?$auto_" ascii /* score: '21.00'*/
      $s30 = "?SetActiveTemporaryTarget@BOCommandHandler@@SAXPAV1@@Z" fullword ascii /* score: '21.00'*/
      $s31 = "?DoCSExecute@BOCSHelper@@SA?AW4Status@ConnectionServer@@PAVjob_thread@@AAV?$ibo_ptr@UJobResultSet@ConnectionServer@@@@AAV?$auto_" ascii /* score: '21.00'*/
      $s32 = "?OnCommand@BORootDialog@@UAA_NAAVBOCommand@@@Z" fullword ascii /* score: '20.00'*/
      $s33 = "??0BOEditSqlDlg@@QAE@PAVBOCommandHandler@@PAVBODialog@@PAVBOString@@AAV3@PAVBOBdInfo@@_NV?$ibo_ptr@UJobResultSet@ConnectionServe" ascii /* score: '20.00'*/
      $s34 = "cs_helpers.dll" fullword ascii /* score: '20.00'*/
      $s35 = "??0BOEditSqlDlg@@QAE@PAVBOCommandHandler@@PAVBODialog@@PAVBOString@@AAV3@PAVBOBdInfo@@_NV?$ibo_ptr@UJobResultSet@ConnectionServe" ascii /* score: '20.00'*/
      $s36 = "?Process@BOGetDirectoryDialog@@QAAPAVBODirectory@@PAV2@PBDK@Z" fullword ascii /* score: '20.00'*/
      $s37 = "cpi18n.dll" fullword ascii /* score: '20.00'*/
      $s38 = "??0MgrGeneralParameter@@QAE@PAVBOCommandHandler@@PAVBOTabDialog@@PAVBOSession@@PAVBOBusClient@@PAVBOUniverseGeneralParam@@_N5PAX" ascii /* score: '20.00'*/
      $s39 = "?OnUpdateCommandStatus@BORootDialog@@UAA_NAAVBOCommandStatus@@@Z" fullword ascii /* score: '20.00'*/
      $s40 = "i18n.dll" fullword ascii /* score: '20.00'*/
      $s41 = "??0MgrGeneralParameter@@QAE@PAVBOCommandHandler@@PAVBOTabDialog@@PAVBOSession@@PAVBOBusClient@@PAVBOUniverseGeneralParam@@_N5PAX" ascii /* score: '20.00'*/
      $s42 = "-- IMallocSpy Free - [%s]" fullword wide /* score: '20.00'*/
      $s43 = "-vm \"%s\\bin\\javaw.exe\" %s" fullword ascii /* score: '19.00'*/
      $s44 = "-vm \"%s\\bin\\javaw.exe\" %s %s" fullword ascii /* score: '19.00'*/
      $s45 = "AutoUniverses::Export ----->>>>ERROR exportUnivers" fullword ascii /* score: '19.00'*/
      $s46 = "MallocSpy" fullword ascii /* base64 encoded string 'jYhq*r' */ /* score: '19.00'*/
      $s47 = "d:\\a42sr32\\win32_x86\\release\\pdb\\UniverseDesigner\\designer.pdb" fullword ascii /* score: '19.00'*/
      $s48 = "MallocSpyDumpLeaks" fullword wide /* score: '19.00'*/
      $s49 = "-- IMallocSpy TAILSIGNATURE Corrupted! - 0x%08x, ID=%08lu, %lu bytes" fullword wide /* score: '19.00'*/
      $s50 = "?CheckPasswords@CBODocument@@MAA_NVBOString@@0PBDAA_N2PAVBOFileDescriptor@@@Z" fullword ascii /* score: '18.00'*/
      $s51 = "?Process@BOSaveAsFileDialog@@QAAPAVBOFileDescriptor@@PBDPAVBODirectory@@0W4BOInternalFileType@@0K_N33@Z" fullword ascii /* score: '18.00'*/
      $s52 = "dsCmdToolLoginAs" fullword ascii /* score: '18.00'*/
      $s53 = "?GetHTTPSessionConfiguration@BOWebParameters@@QAAAAVHTTPSessionConfiguration@@XZ" fullword ascii /* score: '18.00'*/
      $s54 = "?GUIGetScriptingErrorText@@YAPAVBOString@@XZ" fullword ascii /* score: '18.00'*/
      $s55 = "?GetDPReportCustomization@BODPDescriptor@@QBAPAVBODPReportCustomization@@XZ" fullword ascii /* score: '18.00'*/
      $s56 = "?GetUnvDescription@BOImportUnvInfo@@QBAABVBOString@@XZ" fullword ascii /* score: '18.00'*/
      $s57 = "?CheckPasswords@CBODocument@@MAA_NPBD00AA_N1PAVBOFileDescriptor@@@Z" fullword ascii /* score: '18.00'*/
      $s58 = "?Process@BOOpenFileDialog@@QAAPAVBOFileDescriptor@@PAVBODirectory@@PBD1K_NKH@Z" fullword ascii /* score: '18.00'*/
      $s59 = "ExecuteWT$" fullword ascii /* score: '18.00'*/
      $s60 = ".?AVCCmdTargetForDesignerCollection@@" fullword ascii /* score: '17.00'*/
      $s61 = "?GetPasswords@BOFCDocEngine@@MAA_NPAVBOResourceDesc@@AAVBOString@@11@Z" fullword ascii /* score: '17.00'*/
      $s62 = ".?AV?$CTypedPtrList@VCObList@@PAVCCmdTargetBase@@@@" fullword ascii /* score: '17.00'*/
      $s63 = "??0BOFormatDialog@@QAE@PAVBOCommandHandler@@PAVBODialog@@_N@Z" fullword ascii /* score: '17.00'*/
      $s64 = "?GetMessageString@CUICommand@@UAEXAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z" fullword ascii /* score: '17.00'*/
      $s65 = "?GetCmdTarget@CBOWinApp@@UAEPAVCCmdTarget@@XZ" fullword ascii /* score: '17.00'*/
      $s66 = "?GetCurrentTabIndex@BOTabDialog@@UAAEXZ" fullword ascii /* score: '17.00'*/
      $s67 = "??0BOTab@@QAE@PAVBOCommandHandler@@PAVBOTabDialog@@@Z" fullword ascii /* score: '17.00'*/
      $s68 = "?SetTooltipString@CUICommand@@UAEXAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z" fullword ascii /* score: '17.00'*/
      $s69 = "?GetEditText@CUICommandForFormulaBar@@UBEXAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z" fullword ascii /* score: '17.00'*/
      $s70 = "?execute@job_thread@@QAA?AW4Status@ConnectionServer@@V?$ibo_ptr@UJobResultSet@ConnectionServer@@@@PAVResultSet@3@@Z" fullword ascii /* score: '17.00'*/
      $s71 = "?GetMenuStringW@CUICommand@@UAEXAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@H@Z" fullword ascii /* score: '17.00'*/
      $s72 = "?GetMessageString@CUIMDIFrameWnd@@MBEXIAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z" fullword ascii /* score: '17.00'*/
      $s73 = "?OnCommand@BOFakeCommandHandler@@UAA_NAAVBOCommand@@@Z" fullword ascii /* score: '17.00'*/
      $s74 = "??0BODialogView@@QAE@PAVBOCommandHandler@@@Z" fullword ascii /* score: '17.00'*/
      $s75 = ".?AVBOFakeCommandHandler@@" fullword ascii /* score: '17.00'*/
      $s76 = "?SaveTemporaryIfNecessary@BOFCDocEngine@@UAAPAVBOFileDescriptor@@XZ" fullword ascii /* score: '17.00'*/
      $s77 = "??0MgrGovernorParameter@@QAE@PAVBOCommandHandler@@PAVBOTabDialog@@PAVBOUniverseGovernorParam@@_NPAVBOBusClient@@3@Z" fullword ascii /* score: '17.00'*/
      $s78 = "??0BOTabDialog@@QAE@PAVBOCommandHandler@@PAVBODialog@@_N2@Z" fullword ascii /* score: '17.00'*/
      $s79 = "?OnCommand@BOListDialog@@UAA_NI@Z" fullword ascii /* score: '17.00'*/
      $s80 = "??0BOStdTabDialog@@QAE@ABVBOString@@_NKPAVBOCommandHandler@@PAVBODialog@@11@Z" fullword ascii /* score: '17.00'*/
      $s81 = "?OnUpdateCommandStatus@BOListDialog@@UAA_NAAVBOCommandStatus@@@Z" fullword ascii /* score: '17.00'*/
      $s82 = "?HasContentChanged@CUICommandForFormulaBar@@UBEHXZ" fullword ascii /* score: '17.00'*/
      $s83 = "?GetPasswords@BOFCDocEngine@@UAAJAAVBOString@@0@Z" fullword ascii /* score: '17.00'*/
      $s84 = "??0BOUnvEditSqlDlg@@QAE@PAVBOCommandHandler@@PAVBODialog@@AAVBOString@@PAVBOUniverse@@_N4@Z" fullword ascii /* score: '17.00'*/
      $s85 = "?OnCommand@CGUIDialog@@MAEHIJ@Z" fullword ascii /* score: '17.00'*/
      $s86 = "?GetTooltipString@CUICommandForFormulaBar@@UAEXAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@H@Z" fullword ascii /* score: '17.00'*/
      $s87 = ".?AVCCmdTargetBase@@" fullword ascii /* score: '17.00'*/
      $s88 = "?GetParentDialog@BORootTab@@QAAPAVBOTabDialog@@XZ" fullword ascii /* score: '17.00'*/
      $s89 = "??0BODialog@@QAE@PAVBOCommandHandler@@PAV0@_N2@Z" fullword ascii /* score: '17.00'*/
      $s90 = "?SaveTemporary@DesDocEngine@@UAAPAVBOFileDescriptor@@XZ" fullword ascii /* score: '17.00'*/
      $s91 = "??0MgrSQLParameter@@QAE@PAVBOCommandHandler@@PAVBOTabDialog@@PAVBOUniverseSQLParam@@_NPAVBOBusClient@@PAVBOUniverseGeneralParam@" ascii /* score: '17.00'*/
      $s92 = "?OnActivateTarget@BOCommandHandler@@UAAXXZ" fullword ascii /* score: '17.00'*/
      $s93 = "?OnUpdateCommandStatus@BOFakeCommandHandler@@UAA_NAAVBOCommandStatus@@@Z" fullword ascii /* score: '17.00'*/
      $s94 = "http://sv.symcb.com/sv.crt0" fullword ascii /* score: '17.00'*/
      $s95 = "CCmdTargetBase" fullword ascii /* score: '17.00'*/
      $s96 = "?GetTooltipString@CUICommand@@UAEXAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@H@Z" fullword ascii /* score: '17.00'*/
      $s97 = ".?AV?$_CTypedPtrList@VCObList@@PAVCCmdTargetBase@@@@" fullword ascii /* score: '17.00'*/
      $s98 = "?ReleaseTemporary@DesDocEngine@@UAAXPAVBOFileDescriptor@@@Z" fullword ascii /* score: '17.00'*/
      $s99 = "-->GetConnections" fullword ascii /* score: '17.00'*/
      $s100 = "??0MgrSQLParameter@@QAE@PAVBOCommandHandler@@PAVBOTabDialog@@PAVBOUniverseSQLParam@@_NPAVBOBusClient@@PAVBOUniverseGeneralParam@" ascii /* score: '17.00'*/
      $s101 = "?OnDeactivateTarget@BOCommandHandler@@UAAXXZ" fullword ascii /* score: '17.00'*/
      $s102 = "Save: Command failed" fullword wide /* score: '17.00'*/
      $s103 = "SaveAsPdf: Command failed" fullword wide /* score: '17.00'*/
      $s104 = "-- IMallocSpy Alloc - 0x%08x, ID=%08lu, %lu bytes" fullword wide /* score: '17.00'*/
      $s105 = "-- IMallocSpy PreRealloc - 0x%08x, ID=%08lu, %lu bytes" fullword wide /* score: '17.00'*/
      $s106 = "InprocHandler32 = s 'ole32.dll'" fullword ascii /* score: '16.00'*/
      $s107 = "?VisualFeedback@UIDropTarget@@UAEXPAVUIDragSel@@H@Z" fullword ascii /* score: '16.00'*/
      $s108 = "?IsInDropArea@UIDropTarget@@UAEHPAVUIDragSel@@ABVCPoint@@@Z" fullword ascii /* score: '16.00'*/
      $s109 = "AutoUniverses::Export ----->>>>exportUnivers" fullword ascii /* score: '16.00'*/
      $s110 = "??1UIDropTarget@@UAE@XZ" fullword ascii /* score: '16.00'*/
      $s111 = ".?AVUIDropTarget@@" fullword ascii /* score: '16.00'*/
      $s112 = "?PrepareAllTargetsForDrag@BODropTarget@@SAXXZ" fullword ascii /* score: '16.00'*/
      $s113 = "??0UIDropTarget@@QAE@PAVCUIView@@@Z" fullword ascii /* score: '16.00'*/
      $s114 = "LimitExecutionTimeWW" fullword ascii /* score: '16.00'*/
      $s115 = "?QueryClipboard@UIDropTarget@@UAEPAVUIDragSel@@XZ" fullword ascii /* score: '16.00'*/
      $s116 = "?PrepareAllTargetsForDrag@UIDropTarget@@SAXXZ" fullword ascii /* score: '16.00'*/
      $s117 = "LimitExecutionTimeValueW" fullword ascii /* score: '16.00'*/
      $s118 = "?BufferedExec@BOCursor@@UAA?AUBOSuccess@@XZ" fullword ascii /* score: '16.00'*/
      $s119 = "_[RefreshStructure].log" fullword ascii /* score: '16.00'*/
      $s120 = "LimitExecutionTime" fullword wide /* score: '16.00'*/
      $s121 = "LimitExecutionTimeValue" fullword wide /* score: '16.00'*/
      $s122 = "C:\\Visual_Studio_2015\\VC\\atlmfc\\include\\afxwin1.inl" fullword wide /* score: '16.00'*/
      $s123 = "C:\\Visual_Studio_2015\\VC\\atlmfc\\include\\afxwin2.inl" fullword wide /* score: '16.00'*/
      $s124 = "LoginTimeOutH&" fullword ascii /* score: '15.00'*/
      $s125 = "Login AsWW" fullword ascii /* score: '15.00'*/
      $s126 = "?GetPortalRootURL@BOWebParameters@@QAAPBDXZ" fullword ascii /* score: '15.00'*/
      $s127 = "?Process@BOYesNoDialog@@UAA?AW4BOMsgButton@@ABVBOString@@PBDK@Z" fullword ascii /* score: '15.00'*/
      $s128 = "?OnSaveUserPrefs@BORootDialog@@UAA_NPBD@Z" fullword ascii /* score: '15.00'*/
      $s129 = "?GetExeFileDescriptor@@YAXGAAVBOFileDescriptor@@@Z" fullword ascii /* score: '15.00'*/
      $s130 = "?GetArrayOfVariableIds@BODPDescriptor@@QAAPAVBOArrayULong@@XZ" fullword ascii /* score: '15.00'*/
      $s131 = "?OnCommand@BORootGUIContainer@@UAA_NAAVBOCommand@@@Z" fullword ascii /* score: '15.00'*/
      $s132 = "AutoUniverses::Export ----->>>>ERROR Cannot find universe" fullword ascii /* score: '15.00'*/
      $s133 = "?OnCommand@CUIMDIFrameWnd@@MAEHIJ@Z" fullword ascii /* score: '15.00'*/
      $s134 = "?OnRestoreUserPrefs@BORootTabDialog@@MAA_NPBD@Z" fullword ascii /* score: '15.00'*/
      $s135 = "win32_x86\\TransMgr.exe" fullword ascii /* score: '15.00'*/
      $s136 = "?GetPathFromFilDesc@BOFileDescriptor@@QBA?AUBOSuccess@@AAVBOString@@@Z" fullword ascii /* score: '15.00'*/
      $s137 = "?OnSaveUserPrefs@BORootTabDialog@@MAA_NPBD@Z" fullword ascii /* score: '15.00'*/
      $s138 = "?GetFileName@BOFileDescriptor@@QBAXAAVBOString@@@Z" fullword ascii /* score: '15.00'*/
      $s139 = "?GetFile@BOContainer@@QAAPBVBOFileDescriptor@@XZ" fullword ascii /* score: '15.00'*/
      $s140 = "?GetKeyBinaryValue@@YAJPBD0PAXAAK@Z" fullword ascii /* score: '15.00'*/
      $s141 = "?GetCOMLastErrorMsg@@YA?AVBOString@@J@Z" fullword ascii /* score: '15.00'*/
      $s142 = "?Process@BOInfoDialog@@QAA?AW4BOMsgButton@@ABVBOString@@PBDK1@Z" fullword ascii /* score: '15.00'*/
      $s143 = "??0TraceLogInitExit@TraceLog400@@QAE@XZ" fullword ascii /* score: '15.00'*/
      $s144 = "?GetType@BOFileDescriptor@@QBA?AW4BOInternalFileType@@XZ" fullword ascii /* score: '15.00'*/
      $s145 = "dsCmdToolPasswordWWW" fullword ascii /* score: '15.00'*/
      $s146 = "?GetListLogicalOperators@BOBdInfo@@QAAPAVBOArrayBOString@@XZ" fullword ascii /* score: '15.00'*/
      $s147 = "??1TraceLogInitExit@TraceLog400@@QAE@XZ" fullword ascii /* score: '15.00'*/
      $s148 = "?InitInterfaceForRelogin@CBOWinApp@@MAEHXZ" fullword ascii /* score: '15.00'*/
      $s149 = "?GetFileName@BOFileDescriptor@@QBAPBDXZ" fullword ascii /* score: '15.00'*/
      $s150 = "?OnUpdateCommandStatus@BORootGUIContainer@@UAA_NAAVBOCommandStatus@@@Z" fullword ascii /* score: '15.00'*/
      $s151 = "?GetFileDescriptor@BODirectory@@QBAABVBOFileDescriptor@@XZ" fullword ascii /* score: '15.00'*/
      $s152 = "?ProcessHelpMsg@CUIMDIFrameWnd@@UAEHAAUtagMSG@@PAK@Z" fullword ascii /* score: '15.00'*/
      $s153 = "?MDIGetSafeActive@CUIMDIFrameWndSizeDock@@QBEPAVCMDIChildWnd@@PAH@Z" fullword ascii /* score: '15.00'*/
      $s154 = "?GetFileDesc@BODirAndFile@@QAAPAVBOFileDescriptor@@XZ" fullword ascii /* score: '15.00'*/
      $s155 = "?GetDPConditionRelations@BODPDescriptor@@QAAAAVBODPConditionRelations@@XZ" fullword ascii /* score: '15.00'*/
      $s156 = "?WINONLY_GetPath@@YAABVBOString@@ABVBOFileDescriptor@@@Z" fullword ascii /* score: '15.00'*/
      $s157 = "?GetDestFileDesc@BOFCDocEngine@@UAAPBVBOFileDescriptor@@XZ" fullword ascii /* score: '15.00'*/
      $s158 = "?GetFullFileName@BOFileDescriptor@@QBA?AUBOSuccess@@AAVBOString@@@Z" fullword ascii /* score: '15.00'*/
      $s159 = "BOUnvRowsTab::Parse CS Error  - Syntax is Wrong" fullword ascii /* score: '15.00'*/
      $s160 = "?WINONLY_GetDirPath@@YAABVBOString@@ABVBOFileDescriptor@@@Z" fullword ascii /* score: '15.00'*/
      $s161 = "?GetFileDesc@DesDocEngine@@UAAPBVBOFileDescriptor@@XZ" fullword ascii /* score: '15.00'*/
      $s162 = "LoginModeWWWH&" fullword ascii /* score: '15.00'*/
      $s163 = "?Process@BOActionDialog@@QAA?AW4BOMsgButton@@ABVBOString@@0PBDK0@Z" fullword ascii /* score: '15.00'*/
      $s164 = "?GetArrayOfCubeIds@BODPDescriptor@@QAAPAVBOArrayULong@@XZ" fullword ascii /* score: '15.00'*/
      $s165 = "?OnRestoreUserPrefs@BORootDialog@@UAA_NPBD@Z" fullword ascii /* score: '15.00'*/
      $s166 = "LoginTimeOut" fullword wide /* score: '15.00'*/
      $s167 = "You should set correctly LoginMode, you wouldn't set a SystemNumber and a LogonGroup" fullword wide /* score: '15.00'*/
      $s168 = "No rights to set LoginTimeOut" fullword wide /* score: '15.00'*/
      $s169 = "LoginAs" fullword wide /* score: '15.00'*/
      $s170 = "Error in Logon" fullword wide /* score: '15.00'*/
      $s171 = "eCommand failed" fullword wide /* score: '15.00'*/
      $s172 = "?DoShowMacrosDialog@CBOWinApp@@UAEXHPAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z" fullword ascii /* score: '14.00'*/
      $s173 = ".?AVBOGetDirectoryDialog@@" fullword ascii /* score: '14.00'*/
      $s174 = ".?AVCGUITableContentViewerDialog@@" fullword ascii /* score: '14.00'*/
      $s175 = "?LangTarget@CBOOriginInfo@@QAEXAAU_Long_Short_Name@@PAD@Z" fullword ascii /* score: '14.00'*/
      $s176 = "PDFUIView::DumpOutLine: " fullword ascii /* score: '14.00'*/
      $s177 = "?InitialUpdateFrame@CBOMultiDocTemplate@@UAEXPAVCFrameWnd@@PAVCDocument@@H@Z" fullword ascii /* score: '14.00'*/
      $s178 = "?GetThisMessageMap@CGUIDialog@@KGPBUAFX_MSGMAP@@XZ" fullword ascii /* score: '14.00'*/
      $s179 = "?GetThisMessageMap@CGUIResizeTabDialog@@KGPBUAFX_MSGMAP@@XZ" fullword ascii /* score: '14.00'*/
      $s180 = "?getCellText@CSGridCtrl@@QBA?AV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@HH@Z" fullword ascii /* score: '14.00'*/
      $s181 = "?GetThisMessageMap@CUISizeDialogBar@@KGPBUAFX_MSGMAP@@XZ" fullword ascii /* score: '14.00'*/
      $s182 = "?GetTabByIndex@BOTabDialog@@UAAPAVBOTab@@E@Z" fullword ascii /* score: '14.00'*/
      $s183 = "?GetPrimaryY_Axis@BODesignFormatDialogExchange@@UAA?AW4BO3State@@AA_N@Z" fullword ascii /* score: '14.00'*/
      $s184 = "?GetThisMessageMap@CResizeDialog@@KGPBUAFX_MSGMAP@@XZ" fullword ascii /* score: '14.00'*/
      $s185 = "?GetResizableWnd@CGUIResizeDialog@@MAEPAVCWnd@@XZ" fullword ascii /* score: '14.00'*/
      $s186 = "?GetRowByRow@BODesignFormatDialogExchange@@UAA?AW4BO3State@@AA_N@Z" fullword ascii /* score: '14.00'*/
      $s187 = "?GetSecondaryY_Axis@BODesignFormatDialogExchange@@UAA?AW4BO3State@@AA_N@Z" fullword ascii /* score: '14.00'*/
      $s188 = "Loading dialog error Code " fullword ascii /* score: '14.00'*/
      $s189 = "Disabled CommandWW" fullword ascii /* score: '14.00'*/
      $s190 = "XUBpeSp1!" fullword ascii /* base64 encoded string ']@iy*u' */ /* score: '14.00'*/
      $s191 = "?GetItemText@CRichListCtrl@@QAE?AV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@HH@Z" fullword ascii /* score: '14.00'*/
      $s192 = "Enabled CommandWWW" fullword ascii /* score: '14.00'*/
      $s193 = "?GetResizableWnd@CResizeDialog@@MAEPAVCWnd@@XZ" fullword ascii /* score: '14.00'*/
      $s194 = "?GetThisMessageMap@CGUIResizeDialog@@KGPBUAFX_MSGMAP@@XZ" fullword ascii /* score: '14.00'*/
      $s195 = "?GetMessageMap@CGUIResizeTabDialog@@MBEPBUAFX_MSGMAP@@XZ" fullword ascii /* score: '14.00'*/
      $s196 = "?GetButtonText@CFlatToolBar@@UAEXHAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z" fullword ascii /* score: '14.00'*/
      $s197 = "-->GetInstallDirectory" fullword ascii /* score: '14.00'*/
      $s198 = "??0Logger@TraceLog400@@AAE@ABV01@@Z" fullword ascii /* score: '14.00'*/
      $s199 = "?GetParameterType@BOFunction@@QAA?AW4OperationType@@G@Z" fullword ascii /* score: '14.00'*/
      $s200 = "?GetCloseMenuItem@CCustToolBar@@UAEHAAV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule sig_5aff860634fadee66a6e8220e67f7ebc88bfcde7a905a2753655706c0252afd1 {
   meta:
      description = "Amadey_MALW - file 5aff860634fadee66a6e8220e67f7ebc88bfcde7a905a2753655706c0252afd1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "5aff860634fadee66a6e8220e67f7ebc88bfcde7a905a2753655706c0252afd1"
   strings:
      $s1 = "cred.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\AppData" fullword ascii /* score: '19.00'*/
      $s3 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\" fullword ascii /* score: '18.00'*/
      $s4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword ascii /* score: '18.00'*/
      $s5 = "POP3 Password" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s6 = "IMAP Password" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s7 = "\\Password" fullword ascii /* score: '13.00'*/
      $s8 = "SOFTWARE\\RealVNC\\WinVNC4\\Password" fullword ascii /* score: '12.00'*/
      $s9 = "SOFTWARE\\TightVNC\\Server\\Password" fullword ascii /* score: '12.00'*/
      $s10 = "SOFTWARE\\TightVNC\\Server\\PasswordViewOnly" fullword ascii /* score: '12.00'*/
      $s11 = "SOFTWARE\\RealVNC\\vncserver\\Password" fullword ascii /* score: '12.00'*/
      $s12 = "IMAP User" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s13 = "Password=" fullword ascii /* score: '12.00'*/
      $s14 = "SOFTWARE\\TigerVNC\\WinVNC4\\Password" fullword ascii /* score: '12.00'*/
      $s15 = "\\.purple\\accounts.xml" fullword ascii /* score: '11.00'*/
      $s16 = "\\Mikrotik\\Winbox\\Addresses.cdb" fullword ascii /* score: '11.00'*/
      $s17 = "\\Wcx_ftp.ini" fullword ascii /* score: '10.00'*/
      $s18 = "SOFTWARE\\TigerVNC\\WinVNC4\\HTTPPortNumber" fullword ascii /* score: '10.00'*/
      $s19 = "SOFTWARE\\TightVNC\\Server\\HttpPort" fullword ascii /* score: '10.00'*/
      $s20 = "\\wcx_ftp.ini" fullword ascii /* score: '10.00'*/
      $s21 = "SOFTWARE\\RealVNC\\vncserver\\HttpPort" fullword ascii /* score: '10.00'*/
      $s22 = "\\HostName" fullword ascii /* score: '10.00'*/
      $s23 = "POP3 User" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s24 = "\\winscp.ini" fullword ascii /* score: '8.00'*/
      $s25 = "\\FileZilla\\sitemanager.xml" fullword ascii /* score: '8.00'*/
      $s26 = "\\UserName" fullword ascii /* score: '8.00'*/
      $s27 = "SOFTWARE\\TightVNC\\Server\\RfbPort" fullword ascii /* score: '7.00'*/
      $s28 = "SOFTWARE\\RealVNC\\WinVNC4\\PortNumber" fullword ascii /* score: '7.00'*/
      $s29 = "Software\\Martin Prikryl\\WinSCP 2\\Sessions\\" fullword ascii /* score: '7.00'*/
      $s30 = " HTTP/1.1" fullword ascii /* score: '7.00'*/
      $s31 = "Software\\Martin Prikryl\\WinSCP 2\\Sessions" fullword ascii /* score: '7.00'*/
      $s32 = "|Stealer_TotalCmd" fullword ascii /* score: '7.00'*/
      $s33 = "<Pass encoding=\"base64\">" fullword ascii /* score: '7.00'*/
      $s34 = "EInOutErrorPl@" fullword ascii /* score: '7.00'*/
      $s35 = "SOFTWARE\\RealVNC\\vncserver\\RfbPort" fullword ascii /* score: '7.00'*/
      $s36 = "SOFTWARE\\TigerVNC\\WinVNC4\\PortNumber" fullword ascii /* score: '7.00'*/
      $s37 = "!!!!<own>!" fullword ascii /* score: '6.00'*/
      $s38 = "<Host>" fullword ascii /* score: '6.00'*/
      $s39 = "</Host>" fullword ascii /* score: '6.00'*/
      $s40 = "winscp" fullword ascii /* score: '5.00'*/
      $s41 = "MiniReg64" fullword ascii /* score: '5.00'*/
      $s42 = "FPUMaskValue" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98'*/ /* Goodware String - occured 23 times */
      $s43 = "Outlook" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 26 times */
      $s44 = "WinSock" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 31 times */
      $s45 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s46 = "TFileStream" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 50 times */
      $s47 = "TPersistent" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 55 times */
      $s48 = "connect" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.57'*/ /* Goodware String - occured 429 times */
      $s49 = "socket" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.55'*/ /* Goodware String - occured 452 times */
      $s50 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.10'*/ /* Goodware String - occured 903 times */
      $s51 = "EZeroDivideto@" fullword ascii /* score: '4.00'*/
      $s52 = "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s53 = "rStealer_MSOutlook" fullword ascii /* score: '4.00'*/
      $s54 = "</password>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s55 = "<User>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s56 = "Exception@k@" fullword ascii /* score: '4.00'*/
      $s57 = "TStringListx!A" fullword ascii /* score: '4.00'*/
      $s58 = "0123456789ABCDEF<i@" fullword ascii /* score: '4.00'*/
      $s59 = "TStringList \"A" fullword ascii /* score: '4.00'*/
      $s60 = "TStringsH A" fullword ascii /* score: '4.00'*/
      $s61 = "</User>" fullword ascii /* score: '4.00'*/
      $s62 = "</protocol>" fullword ascii /* score: '4.00'*/
      $s63 = "0x%.2x%.2x%.2x%.2x%.2x%.2x" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s64 = "4]5i5x5" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s65 = "Stealer_WinSCP" fullword ascii /* score: '4.00'*/
      $s66 = "EVariantBadVarTypeError$" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s67 = "TigerVNC" fullword ascii /* score: '4.00'*/
      $s68 = "Stealer_Pidgin" fullword ascii /* score: '4.00'*/
      $s69 = "<$<,<0<4<8<<<@<D<H<L<\\<|<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s70 = "Stealer_Winbox" fullword ascii /* score: '4.00'*/
      $s71 = "7)7;7@7" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s72 = "> >@>H>L>P>T>X>\\>`>d>h>x>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s73 = "EFilerErrorP" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s74 = "=4=<=@=D=H=L=P=T=X=\\=l=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s75 = "2F2K2P2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s76 = "TCustomVariantTyped" fullword ascii /* score: '4.00'*/
      $s77 = "3,3L3T3X3\\3`3d3h3l3p3t3x3|3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s78 = "Stealer_Var" fullword ascii /* score: '4.00'*/
      $s79 = "1$1u1|1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s80 = ":Z;m;y;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s81 = "UserName=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s82 = "=$=,=0=4=8=<=@=D=H=L=\\=|=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s83 = "</Pass>" fullword ascii /* score: '4.00'*/
      $s84 = "TightVNC" fullword ascii /* score: '4.00'*/
      $s85 = "Stealer_VNC" fullword ascii /* score: '4.00'*/
      $s86 = "1 1(1,1014181<1@1D1H1b1j1r1z1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s87 = "PStealer_FileZilla" fullword ascii /* score: '4.00'*/
      $s88 = "Cannot assign a %s to a %s%String list does not allow duplicates" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s89 = "?(?H?P?T?X?\\?`?d?h?l?p?" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s90 = "< <$<(<,<0<4<8<<<@<T<t<|<" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s91 = "Winbox" fullword ascii /* score: '3.00'*/
      $s92 = "password=" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s93 = "4$4D4L4P4T4X4\\4`4d4h4l4" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s94 = "282@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s95 = "5\"5E5f5" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s96 = "TThreadListtA" fullword ascii /* score: '3.00'*/
      $s97 = "1.2_2y2" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s98 = "588<8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8x8|8" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s99 = "Pidgin" fullword ascii /* score: '3.00'*/
      $s100 = "5ce0d3ad6b4a07a7a35b6e35a7d02f04" ascii /* score: '3.00'*/
      $s101 = "HostName=" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s102 = "Variant or safe array is lockedInvalid variant type conversion" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s103 = "System" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.43'*/ /* Goodware String - occured 2567 times */
      $s104 = "0 040T0\\0`0d0h0l0p0t0x0|0" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s105 = "<password>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s106 = "5\"5*525:5B5J5R5Z5b5j5r5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s107 = "5 5x5|5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s108 = "949@9H9" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s109 = "FileZilla" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s110 = "</name>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s111 = " List capacity out of bounds (%d)" fullword wide /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s112 = "5+63696?6r6" fullword ascii /* score: '1.00'*/
      $s113 = "9$9.9@9R9y9" fullword ascii /* score: '1.00'*/
      $s114 = "3!3N3Y3(4/4" fullword ascii /* score: '1.00'*/
      $s115 = "1!1,1<1L1T1X1\\1`1d1h1l1p1t1x1|1" fullword ascii /* score: '1.00'*/
      $s116 = "1&2<2I2N2`2" fullword ascii /* score: '1.00'*/
      $s117 = "; ;D;n;" fullword ascii /* score: '1.00'*/
      $s118 = "3\"3'3,31363D3N3y3" fullword ascii /* score: '1.00'*/
      $s119 = ">'>->A>K>_>n>" fullword ascii /* score: '1.00'*/
      $s120 = "?.?7?K?Y?m?" fullword ascii /* score: '1.00'*/
      $s121 = "2 2(2,2024282<2@2D2H2X2x2" fullword ascii /* score: '1.00'*/
      $s122 = "6\"6s6{6" fullword ascii /* score: '1.00'*/
      $s123 = "6 7+7@7a7~7" fullword ascii /* score: '1.00'*/
      $s124 = ">J?_?x?" fullword ascii /* score: '1.00'*/
      $s125 = "2'2.2@2R2_2k2x2" fullword ascii /* score: '1.00'*/
      $s126 = "?#?)?.?9???D?O?U?Z?e?k?p?{?" fullword ascii /* score: '1.00'*/
      $s127 = "5 5<5\\5d5h5l5p5t5x5|5" fullword ascii /* score: '1.00'*/
      $s128 = "445I5^5c5p5" fullword ascii /* score: '1.00'*/
      $s129 = "<'<3<@<R<[<(=g=" fullword ascii /* score: '1.00'*/
      $s130 = "9-9?9Q9a9f9k9r9w9" fullword ascii /* score: '1.00'*/
      $s131 = "7 7<7\\7d7h7l7p7t7x7|7" fullword ascii /* score: '1.00'*/
      $s132 = "=!=%=)=-=1=5=9===A=E=I=M=Q=c={=y?}?" fullword ascii /* score: '1.00'*/
      $s133 = ";4<t<~<" fullword ascii /* score: '1.00'*/
      $s134 = "819A9W9u9" fullword ascii /* score: '1.00'*/
      $s135 = "=&=.=6=>=F=N=V=c=o=|=" fullword ascii /* score: '1.00'*/
      $s136 = "=!>t>.?r?w?" fullword ascii /* score: '1.00'*/
      $s137 = "6T7\\7b7h7u7{7" fullword ascii /* score: '1.00'*/
      $s138 = "<#=L=S=Z=*>?>r>" fullword ascii /* score: '1.00'*/
      $s139 = "7\"7S7_7l7~7" fullword ascii /* score: '1.00'*/
      $s140 = "WinSCP" fullword ascii /* score: '1.00'*/
      $s141 = "0080=0B0J0O0m0r0w0|0" fullword ascii /* score: '1.00'*/
      $s142 = "4 4$4(4,4044484<4@4v4" fullword ascii /* score: '1.00'*/
      $s143 = "40484<4@4D4H4L4P4T4X4t4" fullword ascii /* score: '1.00'*/
      $s144 = "?\"?,?6?@?O?Y?k?" fullword ascii /* score: '1.00'*/
      $s145 = ":\":':/:4:=:]:d:s:" fullword ascii /* score: '1.00'*/
      $s146 = "#1K1R1j1" fullword ascii /* score: '1.00'*/
      $s147 = "8K9W9^9p9" fullword ascii /* score: '1.00'*/
      $s148 = "<V<^<i<" fullword ascii /* score: '1.00'*/
      $s149 = ">=>D>[><?G?k?}?" fullword ascii /* score: '1.00'*/
      $s150 = "2-212D2d2l2p2t2x2|2" fullword ascii /* score: '1.00'*/
      $s151 = "0!1G1S1`1r1" fullword ascii /* score: '1.00'*/
      $s152 = "20S0f0n0" fullword ascii /* score: '1.00'*/
      $s153 = "<\"<)<.<8<B<^<e<|<?=N=" fullword ascii /* score: '1.00'*/
      $s154 = "&cred=" fullword ascii /* score: '1.00'*/
      $s155 = "4R4Z4a4" fullword ascii /* score: '1.00'*/
      $s156 = "1\"1D3K3\\3h3" fullword ascii /* score: '1.00'*/
      $s157 = "4=5H5{5" fullword ascii /* score: '1.00'*/
      $s158 = "6\"6)6.666;6D6d6k6z6" fullword ascii /* score: '1.00'*/
      $s159 = "8%999_9s9p;" fullword ascii /* score: '1.00'*/
      $s160 = "4\"424:4\\4o4" fullword ascii /* score: '1.00'*/
      $s161 = "8.8;8F8g8}8" fullword ascii /* score: '1.00'*/
      $s162 = "7.737?7b7" fullword ascii /* score: '1.00'*/
      $s163 = "7K7f7~7" fullword ascii /* score: '1.00'*/
      $s164 = "9G9Z9l9p9t9x9|9" fullword ascii /* score: '1.00'*/
      $s165 = ":3:L:e:v:" fullword ascii /* score: '1.00'*/
      $s166 = "3 3(383<3H3T3X3\\3`3d3" fullword ascii /* score: '1.00'*/
      $s167 = "0,080<0@0D0H0L0P0T0`0m0" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s168 = "3C3^3t3" fullword ascii /* score: '1.00'*/
      $s169 = "0/0;0B0M0_0r0x0" fullword ascii /* score: '1.00'*/
      $s170 = "3 3$3(3,3H3h3p3t3x3|3" fullword ascii /* score: '1.00'*/
      $s171 = "585>5P5h5t5|5" fullword ascii /* score: '1.00'*/
      $s172 = ";\";9;H;_;n;" fullword ascii /* score: '1.00'*/
      $s173 = "0%080P0o0w0" fullword ascii /* score: '1.00'*/
      $s174 = "515E5Q5j5" fullword ascii /* score: '1.00'*/
      $s175 = ": :(:0:8:@:O:[:h:z:" fullword ascii /* score: '1.00'*/
      $s176 = ";\";b;i;};" fullword ascii /* score: '1.00'*/
      $s177 = "<&<-<<<P<t<" fullword ascii /* score: '1.00'*/
      $s178 = "?(?8?D?H?P?T?X?\\?`?d?h?l?p?t?x?|?" fullword ascii /* score: '1.00'*/
      $s179 = "6,64686<6@6D6H6L6P6T6p6" fullword ascii /* score: '1.00'*/
      $s180 = "343<3@3D3H3L3P3T3X3\\3p3" fullword ascii /* score: '1.00'*/
      $s181 = ">&>.>6>>>" fullword ascii /* score: '1.00'*/
      $s182 = ">,>4>8><>@>D>H>L>P>T>l>" fullword ascii /* score: '1.00'*/
      $s183 = "6b30a;ec2d7_h7`6f" fullword ascii /* score: '1.00'*/
      $s184 = ";$<1<`<" fullword ascii /* score: '1.00'*/
      $s185 = "2(3R3b3m3s3{3" fullword ascii /* score: '1.00'*/
      $s186 = "5T6m:}:" fullword ascii /* score: '1.00'*/
      $s187 = "7?7Q7n7" fullword ascii /* score: '1.00'*/
      $s188 = "WinScp" fullword ascii /* score: '1.00'*/
      $s189 = "=A=_=|=" fullword ascii /* score: '1.00'*/
      $s190 = "3*3?3T3|3" fullword ascii /* score: '1.00'*/
      $s191 = "0&00070" fullword ascii /* score: '1.00'*/
      $s192 = "0.060K0S0p0}0Z1M2r2" fullword ascii /* score: '1.00'*/
      $s193 = "8;9J9a9" fullword ascii /* score: '1.00'*/
      $s194 = ";$;6;<;\\;d;h;l;p;t;x;|;" fullword ascii /* score: '1.00'*/
      $s195 = "2\\3f3k3u3" fullword ascii /* score: '1.00'*/
      $s196 = "3!414O4" fullword ascii /* score: '1.00'*/
      $s197 = "4w5/6G6X6t6" fullword ascii /* score: '1.00'*/
      $s198 = "8+9:9T9f9" fullword ascii /* score: '1.00'*/
      $s199 = ">$?+?f?" fullword ascii /* score: '1.00'*/
      $s200 = ">\">,>?>o>" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule fff0ebef752c4e657f04529267347416 {
   meta:
      description = "Amadey_MALW - file fff0ebef752c4e657f04529267347416"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "3d4fa915ede8b3a7d95155694abfe13c3ad26a65545fe1635797ff200ccdcb40"
   strings:
      $s1 = "C:\\xeyes.pdb" fullword ascii /* score: '25.00'*/
      $s2 = "voygcuadage.exe" fullword wide /* score: '22.00'*/
      $s3 = "kepofuy.exe" fullword ascii /* score: '22.00'*/
      $s4 = "FFFFFFFFF4" ascii /* reversed goodware string '4FFFFFFFFF' */ /* score: '15.00'*/
      $s5 = "vvvvvv," fullword ascii /* reversed goodware string ',vvvvvv' */ /* score: '14.00'*/
      $s6 = "Xagurorim zedojokit hikomulaHFal digan covorujiyexabih zetod bahohibinabok xupefamebubu ficexunidayid/Loye warojeguzuco pifayudo" wide /* score: '12.00'*/
      $s7 = "runexobozez" fullword ascii /* score: '11.00'*/
      $s8 = "0Nukipixujabed jova mucater deyon denu jeyacidebo=Rosehozixenemac zikudizufu juxivodasede sogipamoco sijeneluhaBPipubey mofijodi" wide /* score: '10.00'*/
      $s9 = "=CntF:\\" fullword ascii /* score: '10.00'*/
      $s10 = ">JMnSC:\"" fullword ascii /* score: '10.00'*/
      $s11 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s12 = "@GetVice@0" fullword ascii /* score: '9.00'*/
      $s13 = ";Vewezacuj lorumozila yabo yugigot bocetisezibatin var gemig[Wulitocedala puyinimipotama nozi jeyavo kafigapur nilela dobe jecoh" wide /* score: '9.00'*/
      $s14 = "* c&y&" fullword ascii /* score: '9.00'*/
      $s15 = "* :rMJ" fullword ascii /* score: '9.00'*/
      $s16 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s17 = "bvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s18 = "vvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s19 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s20 = "nvvvvvvvvvvvvvnnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s21 = "kevvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s22 = "vvvvvvvvvvvvvvvvvvg" fullword ascii /* score: '8.00'*/
      $s23 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvs" fullword ascii /* score: '8.00'*/
      $s24 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s25 = "vvvvvvvvvvn" fullword ascii /* score: '8.00'*/
      $s26 = "nvvvvvvvvvvvvvnnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s27 = "vvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s28 = "vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s29 = "nvvvvvvvvvvn" fullword ascii /* score: '8.00'*/
      $s30 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s31 = "rqmnmso" fullword ascii /* score: '8.00'*/
      $s32 = "rinakimuhuzafoluj" fullword ascii /* score: '8.00'*/
      $s33 = "jivuzibibewuyadoruxecidowuguxodolenatumefefirarenolepiwurupuxoyijekoruhe" fullword wide /* score: '8.00'*/
      $s34 = "0}y3%BTpvD%:" fullword ascii /* score: '8.00'*/
      $s35 = "EmrT3!." fullword ascii /* score: '8.00'*/
      $s36 = "ccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s37 = "ProductVersions" fullword wide /* score: '7.00'*/
      $s38 = "Daporesen cic.Nek hozuheritihos kenelatokupuj jurubenidajiza" fullword wide /* score: '7.00'*/
      $s39 = "Beduyofimux xogozehuyawJNenayebinikove vuhanuzi gariluru jimagig rocesesun jim tedaj mupituhi vuvu+Gejipo puzikaha zuga mesohoyo" wide /* score: '7.00'*/
      $s40 = "bam.LjB" fullword ascii /* score: '7.00'*/
      $s41 = "2&go:\\" fullword ascii /* score: '7.00'*/
      $s42 = ".dJ:\"#" fullword ascii /* score: '7.00'*/
      $s43 = "qD:\"C[" fullword ascii /* score: '7.00'*/
      $s44 = ".:7t:\\" fullword ascii /* score: '7.00'*/
      $s45 = "FFFFFFFFFFFFFFFFFFF" ascii /* score: '6.50'*/
      $s46 = "Budefup" fullword wide /* score: '6.00'*/
      $s47 = "1.7.38.44" fullword wide /* score: '6.00'*/
      $s48 = "Johiwivojunexar" fullword wide /* score: '6.00'*/
      $s49 = "Kenegodiza sikimec covituwutaPPuloperehodop xew pazefom lurefazuyod gesoru gadumolop facelimame lihobiboc tibe#Lovul vefewaripuy" wide /* score: '5.00'*/
      $s50 = "Muxewejakoni/Himekapusacec xumayojub baj curi gofirakokiboluYGafayecixuvux now gulamakavidicu ziyuyedin zunixoregomofa zit laxek" wide /* score: '5.00'*/
      $s51 = "+ <m~C[" fullword ascii /* score: '5.00'*/
      $s52 = "|{* 9u" fullword ascii /* score: '5.00'*/
      $s53 = "MyggOG84" fullword ascii /* score: '5.00'*/
      $s54 = "}9&fQ -" fullword ascii /* score: '5.00'*/
      $s55 = "jSAMpE" fullword ascii /* score: '5.00'*/
      $s56 = "}[<m* " fullword ascii /* score: '5.00'*/
      $s57 = "qBbpCY0" fullword ascii /* score: '5.00'*/
      $s58 = " /kwbw" fullword ascii /* score: '5.00'*/
      $s59 = "eLJTPk2" fullword ascii /* score: '5.00'*/
      $s60 = "0(Z -d" fullword ascii /* score: '5.00'*/
      $s61 = ";/SAM*" fullword ascii /* score: '5.00'*/
      $s62 = "Z0S%J%" fullword ascii /* score: '5.00'*/
      $s63 = "+ $-%W_Z" fullword ascii /* score: '5.00'*/
      $s64 = " -2ip5" fullword ascii /* score: '5.00'*/
      $s65 = "U3{- [" fullword ascii /* score: '5.00'*/
      $s66 = "bs- ^8" fullword ascii /* score: '5.00'*/
      $s67 = "szihbm" fullword ascii /* score: '5.00'*/
      $s68 = "n@- 4L!/CP]e" fullword ascii /* score: '5.00'*/
      $s69 = "x^f?* " fullword ascii /* score: '5.00'*/
      $s70 = "_v4a -[Q99" fullword ascii /* score: '5.00'*/
      $s71 = "e* vnG~?" fullword ascii /* score: '5.00'*/
      $s72 = "uqXoNV8" fullword ascii /* score: '5.00'*/
      $s73 = "mMYqCy0" fullword ascii /* score: '5.00'*/
      $s74 = "\\P-.wxD+DXTK" fullword ascii /* score: '5.00'*/
      $s75 = "TQcikvQe5" fullword ascii /* score: '5.00'*/
      $s76 = "]#1#+ c" fullword ascii /* score: '5.00'*/
      $s77 = "SUVWuD3" fullword ascii /* score: '5.00'*/
      $s78 = "wLMJgw1" fullword ascii /* score: '5.00'*/
      $s79 = "4vQE- <" fullword ascii /* score: '5.00'*/
      $s80 = "siia* " fullword ascii /* score: '5.00'*/
      $s81 = "sfqxcy" fullword ascii /* score: '5.00'*/
      $s82 = "?+ w_G4chE0" fullword ascii /* score: '5.00'*/
      $s83 = "/Z+* zM" fullword ascii /* score: '5.00'*/
      $s84 = "avglgl" fullword ascii /* score: '5.00'*/
      $s85 = "6 -7/[" fullword ascii /* score: '5.00'*/
      $s86 = "#$ny -W5" fullword ascii /* score: '5.00'*/
      $s87 = "z- Cv5" fullword ascii /* score: '5.00'*/
      $s88 = "# &Mur" fullword ascii /* score: '5.00'*/
      $s89 = "lvvvvvvvvvvvvvvvvvvvvv;" fullword ascii /* score: '4.00'*/
      $s90 = "vvvvvvvvvvvvvvvvvvvvvvvvvB" fullword ascii /* score: '4.00'*/
      $s91 = "$ hvvvvvvvvvvvvvvvvvvv2" fullword ascii /* score: '4.00'*/
      $s92 = ".www.&" fullword ascii /* score: '4.00'*/
      $s93 = "uSFvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s94 = "(vvvvvvvv" fullword ascii /* score: '4.00'*/
      $s95 = "_Fvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s96 = "IHvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s97 = "eeee{{{" fullword ascii /* score: '4.00'*/
      $s98 = "Boruka hipeturuhog" fullword ascii /* score: '4.00'*/
      $s99 = "R0U1vvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s100 = "vvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s101 = "%vvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s102 = "L<W]vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s103 = "vvvvvvvvvvvn{" fullword ascii /* score: '4.00'*/
      $s104 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv-vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s105 = "~8evvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s106 = "vvvvvvvvvvv," fullword ascii /* score: '4.00'*/
      $s107 = "Qr!/{Mvvvvvvvvvvvvvvvvvvvvvvvvvj" fullword ascii /* score: '4.00'*/
      $s108 = "%vvvvvvvvvvvvvvvvvvA" fullword ascii /* score: '4.00'*/
      $s109 = "StringFileInform" fullword wide /* score: '4.00'*/
      $s110 = "Copyrighz (C) 2020, wodkagudy" fullword wide /* score: '4.00'*/
      $s111 = "Pucewuhon repisotujoduxoyNJiyipixohorag deceh zoxebej nek fogi nayikux dufa sebumili mugizefilaret wegipJNugakidegamew navisoxud" wide /* score: '4.00'*/
      $s112 = "Wobetesido suvesebuxomelot" fullword wide /* score: '4.00'*/
      $s113 = "Hoxazawiwod fupucu" fullword wide /* score: '4.00'*/
      $s114 = "Moba futumibe(Tanudipa wupavabifinax xemamaweladen marUPofunoc temamojavopu kajenulecola harilupulaz xuyiliso xucutuhabebe yujoy" wide /* score: '4.00'*/
      $s115 = "Bajuhozaximepo nitisi" fullword wide /* score: '4.00'*/
      $s116 = "Hilegehihedo mekanisozu2Likarivasiga wejehumubere huhugoma vijutezumav fav" fullword wide /* score: '4.00'*/
      $s117 = "Bimecefef hefayuguxogesIVeguwakan rojiyutirabila tuxij dexa jehoposabem tijoxexuj vixaxasiju gowe8Rigoniropigox kujakiyasu huba " wide /* score: '4.00'*/
      $s118 = "Ceh kijakadiniradow fafodarix2Zuvemabo dodap cuhuro bahudorebihoke gahodayikukew" fullword wide /* score: '4.00'*/
      $s119 = "8Hofozopuyawa xodolivabic faleki huvidobeyawo kigepirolef" fullword wide /* score: '4.00'*/
      $s120 = "AFSe='d" fullword ascii /* score: '4.00'*/
      $s121 = "FmZy(;?" fullword ascii /* score: '4.00'*/
      $s122 = "{dzzwE|$" fullword ascii /* score: '4.00'*/
      $s123 = "wbPrNuZ" fullword ascii /* score: '4.00'*/
      $s124 = "LnzV%at" fullword ascii /* score: '4.00'*/
      $s125 = "ZtYI(s~U" fullword ascii /* score: '4.00'*/
      $s126 = "HYXtaNKF" fullword ascii /* score: '4.00'*/
      $s127 = "FOvv>R>" fullword ascii /* score: '4.00'*/
      $s128 = "%*qgyqt2L" fullword ascii /* score: '4.00'*/
      $s129 = "5PvXD[1(" fullword ascii /* score: '4.00'*/
      $s130 = "bOCpgEU" fullword ascii /* score: '4.00'*/
      $s131 = "\"HEmNeMwS" fullword ascii /* score: '4.00'*/
      $s132 = "ZcDM0Jt" fullword ascii /* score: '4.00'*/
      $s133 = "hGjA.tA" fullword ascii /* score: '4.00'*/
      $s134 = "dFZXN $" fullword ascii /* score: '4.00'*/
      $s135 = "?$?@?L?h?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s136 = "TKAMM=5" fullword ascii /* score: '4.00'*/
      $s137 = "fwcbkvO" fullword ascii /* score: '4.00'*/
      $s138 = ",rxDC)G]" fullword ascii /* score: '4.00'*/
      $s139 = "XksQ/z8" fullword ascii /* score: '4.00'*/
      $s140 = "]FHzGST:2[" fullword ascii /* score: '4.00'*/
      $s141 = "gTia'x]mnb" fullword ascii /* score: '4.00'*/
      $s142 = "FgHzY\"tR+4d" fullword ascii /* score: '4.00'*/
      $s143 = "CytrmU_" fullword ascii /* score: '4.00'*/
      $s144 = "WfOfji<" fullword ascii /* score: '4.00'*/
      $s145 = "vJwtPYDv" fullword ascii /* score: '4.00'*/
      $s146 = "jrWf8uv" fullword ascii /* score: '4.00'*/
      $s147 = "G5iEepK'5" fullword ascii /* score: '4.00'*/
      $s148 = "gLCB>gZ" fullword ascii /* score: '4.00'*/
      $s149 = "MFyb.34" fullword ascii /* score: '4.00'*/
      $s150 = "KRvL='J" fullword ascii /* score: '4.00'*/
      $s151 = "IrWBb3W" fullword ascii /* score: '4.00'*/
      $s152 = ".Tqj'4" fullword ascii /* score: '4.00'*/
      $s153 = "&tRNTVm*" fullword ascii /* score: '4.00'*/
      $s154 = "QCwB`L|" fullword ascii /* score: '4.00'*/
      $s155 = "6eDQA*a$r&" fullword ascii /* score: '4.00'*/
      $s156 = "kgob+p#" fullword ascii /* score: '4.00'*/
      $s157 = "{|}\"STAE?" fullword ascii /* score: '4.00'*/
      $s158 = "YNkH.B:OfKt" fullword ascii /* score: '4.00'*/
      $s159 = "'8(WeMLS9Y[0" fullword ascii /* score: '4.00'*/
      $s160 = "m\"YoLu+>FG`l" fullword ascii /* score: '4.00'*/
      $s161 = "lEDy,xv" fullword ascii /* score: '4.00'*/
      $s162 = "GVrwX]xn" fullword ascii /* score: '4.00'*/
      $s163 = "twTt|9*" fullword ascii /* score: '4.00'*/
      $s164 = "XfaRf;iLT;=" fullword ascii /* score: '4.00'*/
      $s165 = "FpYZXOs" fullword ascii /* score: '4.00'*/
      $s166 = "vgEU0Ww" fullword ascii /* score: '4.00'*/
      $s167 = "fkXnq`G" fullword ascii /* score: '4.00'*/
      $s168 = "TbJTRh&" fullword ascii /* score: '4.00'*/
      $s169 = "XvmaArrU" fullword ascii /* score: '4.00'*/
      $s170 = "hO.SOt" fullword ascii /* score: '4.00'*/
      $s171 = "[QWEDWY," fullword ascii /* score: '4.00'*/
      $s172 = "HFeB/m6p" fullword ascii /* score: '4.00'*/
      $s173 = "RADI0E[" fullword ascii /* score: '4.00'*/
      $s174 = "xAOgJg^V" fullword ascii /* score: '4.00'*/
      $s175 = "=VrZzW`z" fullword ascii /* score: '4.00'*/
      $s176 = "GhVh=vp" fullword ascii /* score: '4.00'*/
      $s177 = "gfdPJ/w" fullword ascii /* score: '4.00'*/
      $s178 = "6p.HwE" fullword ascii /* score: '4.00'*/
      $s179 = "LFucu>[" fullword ascii /* score: '4.00'*/
      $s180 = "vDfvZ?" fullword ascii /* score: '4.00'*/
      $s181 = "FTZi]e8>B^" fullword ascii /* score: '4.00'*/
      $s182 = "yItfegQ" fullword ascii /* score: '4.00'*/
      $s183 = "lVlYKqX_" fullword ascii /* score: '4.00'*/
      $s184 = "wqLFW{,j" fullword ascii /* score: '4.00'*/
      $s185 = "jGjVJ\"" fullword ascii /* score: '4.00'*/
      $s186 = ".hsN't:OixD" fullword ascii /* score: '4.00'*/
      $s187 = "VApU+76Q>" fullword ascii /* score: '4.00'*/
      $s188 = "erUO&bo" fullword ascii /* score: '4.00'*/
      $s189 = "6clYmXq)l;1" fullword ascii /* score: '4.00'*/
      $s190 = "WA.dNA" fullword ascii /* score: '4.00'*/
      $s191 = "TgTT.=L" fullword ascii /* score: '4.00'*/
      $s192 = "yARhb2E" fullword ascii /* score: '4.00'*/
      $s193 = "8oKgIEFq" fullword ascii /* score: '4.00'*/
      $s194 = "scccc?I" fullword ascii /* score: '4.00'*/
      $s195 = "zhvD~1q '" fullword ascii /* score: '4.00'*/
      $s196 = "jFMd\"g!" fullword ascii /* score: '4.00'*/
      $s197 = "lfPq9.~%" fullword ascii /* score: '4.00'*/
      $s198 = "irwmz^<&" fullword ascii /* score: '4.00'*/
      $s199 = "BnZxoni" fullword ascii /* score: '4.00'*/
      $s200 = "Kcbzt_8!" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule sig_2964ea014ca6c3770dd7e28339348eb7 {
   meta:
      description = "Amadey_MALW - file 2964ea014ca6c3770dd7e28339348eb7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "a1b0074cbd56956cc94e6161361f8f7407075f2903d14d082c1006f411bec90a"
   strings:
      $s1 = "voygcuadage.exe" fullword wide /* score: '22.00'*/
      $s2 = "koga.exe" fullword ascii /* score: '22.00'*/
      $s3 = "C:\\yokugu\\gemupocu tuhokanaye.pdb" fullword ascii /* score: '20.00'*/
      $s4 = "vvvvvv," fullword ascii /* reversed goodware string ',vvvvvv' */ /* score: '14.00'*/
      $s5 = "Xagurorim zedojokit hikomulaHFal digan covorujiyexabih zetod bahohibinabok xupefamebubu ficexunidayid/Loye warojeguzuco pifayudo" wide /* score: '12.00'*/
      $s6 = "Daporesen cic.Nek hozuheritihos kenelatokupuj jurubenidajiza+Mevu zigu rubacoluye jipebe ciheyevasetotot" fullword wide /* score: '12.00'*/
      $s7 = "runexobozez" fullword ascii /* score: '11.00'*/
      $s8 = "0Nukipixujabed jova mucater deyon denu jeyacidebo=Rosehozixenemac zikudizufu juxivodasede sogipamoco sijeneluhaBPipubey mofijodi" wide /* score: '10.00'*/
      $s9 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s10 = "@GetVice@0" fullword ascii /* score: '9.00'*/
      $s11 = ";Vewezacuj lorumozila yabo yugigot bocetisezibatin var gemig[Wulitocedala puyinimipotama nozi jeyavo kafigapur nilela dobe jecoh" wide /* score: '9.00'*/
      $s12 = "@GetFirstVice@0" fullword ascii /* score: '9.00'*/
      $s13 = "Tiholavogi givisusihiki babacose jeyevaxolewune romipereveju" fullword wide /* score: '9.00'*/
      $s14 = "bvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s15 = "vvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s16 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s17 = "kevvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s18 = "vvvvvvvvvvvvvvvvvvg" fullword ascii /* score: '8.00'*/
      $s19 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvs" fullword ascii /* score: '8.00'*/
      $s20 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s21 = "vvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s22 = "vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s23 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s24 = "budesorozefabijicu" fullword wide /* score: '8.00'*/
      $s25 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" fullword ascii /* score: '8.00'*/
      $s26 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ascii /* score: '8.00'*/
      $s27 = "vxxxxxxxxxxxxxxxx" fullword ascii /* score: '8.00'*/
      $s28 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ascii /* score: '8.00'*/
      $s29 = "ckxxxxxxxx" fullword ascii /* score: '8.00'*/
      $s30 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" fullword ascii /* score: '8.00'*/
      $s31 = "mxxxxxxxxxk" fullword ascii /* score: '8.00'*/
      $s32 = "vxxxxxxx" fullword ascii /* score: '8.00'*/
      $s33 = "kxxxxxxxxxxi" fullword ascii /* score: '8.00'*/
      $s34 = "ixxxxxxxk" fullword ascii /* score: '8.00'*/
      $s35 = "xxxxxxxxxxxxxxv" fullword ascii /* score: '8.00'*/
      $s36 = "lidulupupocebunejohojenivumaz" fullword wide /* score: '8.00'*/
      $s37 = "femaseparukomatul" fullword wide /* score: '8.00'*/
      $s38 = "ProductVersions" fullword wide /* score: '7.00'*/
      $s39 = "Beduyofimux xogozehuyawJNenayebinikove vuhanuzi gariluru jimagig rocesesun jim tedaj mupituhi vuvu+Gejipo puzikaha zuga mesohoyo" wide /* score: '7.00'*/
      $s40 = "Budefup" fullword wide /* score: '6.00'*/
      $s41 = "Megotuzoteneri" fullword ascii /* score: '6.00'*/
      $s42 = "XGuci sevuborigili poxocakef gawituvico dadukolan soviwavitafec tuhonol liyo zilameluxaruZVujun lavicomepit xavedoboxum tinuvovu" wide /* score: '6.00'*/
      $s43 = "Dxxxxxxxx" fullword ascii /* score: '6.00'*/
      $s44 = "Mxxxxxxxxxxxx" fullword ascii /* score: '6.00'*/
      $s45 = "jivuzibibe wuyadoruxecidowuguxodolenatumefefirarenolepiwurupuxoyijekoruhe" fullword wide /* score: '6.00'*/
      $s46 = "1.7.39.18" fullword wide /* score: '6.00'*/
      $s47 = "Kenegodiza sikimec covituwutaPPuloperehodop xew pazefom lurefazuyod gesoru gadumolop facelimame lihobiboc tibe#Lovul vefewaripuy" wide /* score: '5.00'*/
      $s48 = "Muxewejakoni/Himekapusacec xumayojub baj curi gofirakokiboluYGafayecixuvux now gulamakavidicu ziyuyedin zunixoregomofa zit laxek" wide /* score: '5.00'*/
      $s49 = "\\UfZD.&1" fullword ascii /* score: '5.00'*/
      $s50 = "ja0j%+ " fullword ascii /* score: '5.00'*/
      $s51 = "Basiw cujadehocenis" fullword ascii /* score: '4.00'*/
      $s52 = "lvvvvvvvvvvvvvvvvvvvvv;" fullword ascii /* score: '4.00'*/
      $s53 = "vvvvvvvvvvvvvvvvvvvvvvvvvB" fullword ascii /* score: '4.00'*/
      $s54 = "$ hvvvvvvvvvvvvvvvvvvv2" fullword ascii /* score: '4.00'*/
      $s55 = "uSFvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s56 = "4SVWh," fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s57 = "(vvvvvvvv" fullword ascii /* score: '4.00'*/
      $s58 = "_Fvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s59 = "IHvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s60 = "R0U1vvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s61 = "vvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s62 = "%vvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s63 = "L<W]vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s64 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv-vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s65 = "~8evvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s66 = "vvvvvvvvvvv," fullword ascii /* score: '4.00'*/
      $s67 = "Qr!/{Mvvvvvvvvvvvvvvvvvvvvvvvvvj" fullword ascii /* score: '4.00'*/
      $s68 = "%vvvvvvvvvvvvvvvvvvA" fullword ascii /* score: '4.00'*/
      $s69 = "Yamohinifo bowi nenukodabebive goyigavu sofusixuyogo" fullword wide /* score: '4.00'*/
      $s70 = "StringFileInform" fullword wide /* score: '4.00'*/
      $s71 = "Copyrighz (C) 2020, wodkagudy" fullword wide /* score: '4.00'*/
      $s72 = "Pucewuhon repisotujoduxoyNJiyipixohorag deceh zoxebej nek fogi nayikux dufa sebumili mugizefilaret wegipJNugakidegamew navisoxud" wide /* score: '4.00'*/
      $s73 = "Wobetesido suvesebuxomelot" fullword wide /* score: '4.00'*/
      $s74 = "Hoxazawiwod fupucu" fullword wide /* score: '4.00'*/
      $s75 = "Moba futumibe(Tanudipa wupavabifinax xemamaweladen marUPofunoc temamojavopu kajenulecola harilupulaz xuyiliso xucutuhabebe yujoy" wide /* score: '4.00'*/
      $s76 = "Bajuhozaximepo nitisi" fullword wide /* score: '4.00'*/
      $s77 = "Hilegehihedo mekanisozu2Likarivasiga wejehumubere huhugoma vijutezumav fav" fullword wide /* score: '4.00'*/
      $s78 = "Bimecefef hefayuguxogesIVeguwakan rojiyutirabila tuxij dexa jehoposabem tijoxexuj vixaxasiju gowe8Rigoniropigox kujakiyasu huba " wide /* score: '4.00'*/
      $s79 = "Ceh kijakadiniradow fafodarix2Zuvemabo dodap cuhuro bahudorebihoke gahodayikukew" fullword wide /* score: '4.00'*/
      $s80 = "aGfkwh08=" fullword ascii /* score: '4.00'*/
      $s81 = "xxxxxxxxxxxD=W" fullword ascii /* score: '4.00'*/
      $s82 = "zQYq|WYI!{" fullword ascii /* score: '4.00'*/
      $s83 = "JwEAWZWvx" fullword ascii /* score: '4.00'*/
      $s84 = "$JuSz,c--" fullword ascii /* score: '4.00'*/
      $s85 = "xxxxxxxxxxxxxxxxx[" fullword ascii /* score: '4.00'*/
      $s86 = "Jab hilegogonanuvax kahudohozihuvuw nixovovivahapan" fullword ascii /* score: '4.00'*/
      $s87 = "U#srcP`r{" fullword ascii /* score: '4.00'*/
      $s88 = "c~xxxxxxxxxxxxxx" fullword ascii /* score: '4.00'*/
      $s89 = "\"wmrZ&VI~J" fullword ascii /* score: '4.00'*/
      $s90 = "Th\"#IUlh+g'" fullword ascii /* score: '4.00'*/
      $s91 = "NAME!<" fullword ascii /* score: '4.00'*/
      $s92 = "2(=xxxxxxxk" fullword ascii /* score: '4.00'*/
      $s93 = "efNF*\\" fullword ascii /* score: '4.00'*/
      $s94 = "\"Bove!" fullword ascii /* score: '4.00'*/
      $s95 = "jlivhf$" fullword ascii /* score: '4.00'*/
      $s96 = "=xxxxxxx1" fullword ascii /* score: '4.00'*/
      $s97 = "xxxxxxxxxxxxxxM" fullword ascii /* score: '4.00'*/
      $s98 = "`iOgf$o-" fullword ascii /* score: '4.00'*/
      $s99 = "Rixowatekucesen cokipawi" fullword wide /* score: '4.00'*/
      $s100 = "Vijosa xizipoke" fullword wide /* score: '4.00'*/
      $s101 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s102 = "xxxxxxxxxxxxxxxxxxx" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s103 = "#//////" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s104 = "nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '2.00'*/
      $s105 = "xxxxxxxxxxxxxxxxx" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s106 = "\\s1YrI}O-" fullword ascii /* score: '2.00'*/
      $s107 = "\\P12(B" fullword ascii /* score: '2.00'*/
      $s108 = "\\!8/(6$Y" fullword ascii /* score: '2.00'*/
      $s109 = "D8`xhn" fullword ascii /* score: '1.00'*/
      $s110 = "/D@yk95" fullword ascii /* score: '1.00'*/
      $s111 = "HGd1*1xL" fullword ascii /* score: '1.00'*/
      $s112 = "%s %f %c" fullword ascii /* score: '1.00'*/
      $s113 = "!Sbs;-0" fullword ascii /* score: '1.00'*/
      $s114 = "ut~Qx|" fullword ascii /* score: '1.00'*/
      $s115 = "Yav fug" fullword ascii /* score: '1.00'*/
      $s116 = "QLso>8" fullword ascii /* score: '1.00'*/
      $s117 = "-IQhE&&" fullword ascii /* score: '1.00'*/
      $s118 = "Kip sizu" fullword ascii /* score: '1.00'*/
      $s119 = "1.16.46" fullword wide /* score: '1.00'*/
      $s120 = "EXbcs%" fullword ascii /* score: '1.00'*/
      $s121 = "081504b6" wide /* score: '1.00'*/
      $s122 = "R)Rr}p" fullword ascii /* score: '1.00'*/
      $s123 = "b89a!*H}F" fullword ascii /* score: '1.00'*/
      $s124 = "^/\"@^C" fullword ascii /* score: '1.00'*/
      $s125 = "tsytLj" fullword ascii /* score: '1.00'*/
      $s126 = "7Y-l'd" fullword ascii /* score: '1.00'*/
      $s127 = "Lon,`'" fullword ascii /* score: '1.00'*/
      $s128 = "-A{s@jC" fullword ascii /* score: '1.00'*/
      $s129 = "Y[WYUbV" fullword ascii /* score: '1.00'*/
      $s130 = "-E]%wQF" fullword ascii /* score: '1.00'*/
      $s131 = "A!_z_`BV" fullword ascii /* score: '1.00'*/
      $s132 = "<t$7Wqg" fullword ascii /* score: '1.00'*/
      $s133 = "B/n[=G" fullword ascii /* score: '1.00'*/
      $s134 = "3gjoP@" fullword ascii /* score: '1.00'*/
      $s135 = "zD1j<2" fullword ascii /* score: '1.00'*/
      $s136 = "B1kTzj" fullword ascii /* score: '1.00'*/
      $s137 = "M=oQTY" fullword ascii /* score: '1.00'*/
      $s138 = "Cqz`+jC9K" fullword ascii /* score: '1.00'*/
      $s139 = "wgG1fI" fullword ascii /* score: '1.00'*/
      $s140 = "_cqG_zR" fullword ascii /* score: '1.00'*/
      $s141 = "Re`Ts]" fullword ascii /* score: '1.00'*/
      $s142 = "=c:&4(" fullword ascii /* score: '1.00'*/
      $s143 = "6i>UBK" fullword ascii /* score: '1.00'*/
      $s144 = "Y{5K^u" fullword ascii /* score: '1.00'*/
      $s145 = "?t#^?p_" fullword ascii /* score: '1.00'*/
      $s146 = "//////////////////~" fullword ascii /* score: '1.00'*/
      $s147 = "rU\\uk%[" fullword ascii /* score: '1.00'*/
      $s148 = "px1}x.f" fullword ascii /* score: '1.00'*/
      $s149 = "B|LIz;lpl~S" fullword ascii /* score: '1.00'*/
      $s150 = "6?*w:N" fullword ascii /* score: '1.00'*/
      $s151 = "0)wWX5" fullword ascii /* score: '1.00'*/
      $s152 = "1g`D{8" fullword ascii /* score: '1.00'*/
      $s153 = "'2[3\"t" fullword ascii /* score: '1.00'*/
      $s154 = "vRv\\_I" fullword ascii /* score: '1.00'*/
      $s155 = "De6E)P" fullword ascii /* score: '1.00'*/
      $s156 = "Cbe\\1T" fullword ascii /* score: '1.00'*/
      $s157 = "WZ)bCk2" fullword ascii /* score: '1.00'*/
      $s158 = "3zJAO>" fullword ascii /* score: '1.00'*/
      $s159 = "7N8zhs" fullword ascii /* score: '1.00'*/
      $s160 = "uX,2&gp" fullword ascii /* score: '1.00'*/
      $s161 = "USC{;/G" fullword ascii /* score: '1.00'*/
      $s162 = "Q^kIi9" fullword ascii /* score: '1.00'*/
      $s163 = "#K[cSa0b" fullword ascii /* score: '1.00'*/
      $s164 = "T1sHRe" fullword ascii /* score: '1.00'*/
      $s165 = ">]qNy " fullword ascii /* score: '1.00'*/
      $s166 = "s;4Gl3nC" fullword ascii /* score: '1.00'*/
      $s167 = ",E#els" fullword ascii /* score: '1.00'*/
      $s168 = "xsV!q4" fullword ascii /* score: '1.00'*/
      $s169 = "n+\\epr" fullword ascii /* score: '1.00'*/
      $s170 = "Bs\"pRi" fullword ascii /* score: '1.00'*/
      $s171 = "(uF;JU" fullword ascii /* score: '1.00'*/
      $s172 = "nO\"yBR~" fullword ascii /* score: '1.00'*/
      $s173 = "y5f`+H" fullword ascii /* score: '1.00'*/
      $s174 = "gRkrWp" fullword ascii /* score: '1.00'*/
      $s175 = "<jf;|\\&" fullword ascii /* score: '1.00'*/
      $s176 = "4j{X.O" fullword ascii /* score: '1.00'*/
      $s177 = "Z\\iRr)" fullword ascii /* score: '1.00'*/
      $s178 = "^,'~U{" fullword ascii /* score: '1.00'*/
      $s179 = "#Igj?#^?A" fullword ascii /* score: '1.00'*/
      $s180 = "Nv? I)" fullword ascii /* score: '1.00'*/
      $s181 = "]RaMI{" fullword ascii /* score: '1.00'*/
      $s182 = ",h>D+W" fullword ascii /* score: '1.00'*/
      $s183 = "}.;&8z" fullword ascii /* score: '1.00'*/
      $s184 = "SJ*=F\\L" fullword ascii /* score: '1.00'*/
      $s185 = "pH-!q=" fullword ascii /* score: '1.00'*/
      $s186 = "zyL(FB" fullword ascii /* score: '1.00'*/
      $s187 = "u4O_`$" fullword ascii /* score: '1.00'*/
      $s188 = "f'c0n?M" fullword ascii /* score: '1.00'*/
      $s189 = "@|kTt|" fullword ascii /* score: '1.00'*/
      $s190 = ";XvAY=" fullword ascii /* score: '1.00'*/
      $s191 = "a>tPP[Y" fullword ascii /* score: '1.00'*/
      $s192 = "Iv8U|IS" fullword ascii /* score: '1.00'*/
      $s193 = "??u^WZ" fullword ascii /* score: '1.00'*/
      $s194 = "P*BsWf+" fullword ascii /* score: '1.00'*/
      $s195 = "[(xxP3Q" fullword ascii /* score: '1.00'*/
      $s196 = "J:Er2=" fullword ascii /* score: '1.00'*/
      $s197 = "&hh7C`" fullword ascii /* score: '1.00'*/
      $s198 = "%v4/Sxy" fullword ascii /* score: '1.00'*/
      $s199 = "Lpl(a.C" fullword ascii /* score: '1.00'*/
      $s200 = "L/////5" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0 {
   meta:
      description = "Amadey_MALW - file c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0"
   strings:
      $s1 = "!-5(*(\"f" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s2 = "* h@nc<l," fullword ascii /* score: '9.00'*/
      $s3 = "z- /bF" fullword ascii /* score: '9.00'*/
      $s4 = "bssicgdc" fullword ascii /* score: '8.00'*/
      $s5 = "ccslmxpc" fullword ascii /* score: '8.00'*/
      $s6 = "<>@>D>H><?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s7 = "@\"8+ O" fullword ascii /* score: '5.00'*/
      $s8 = " -13eY" fullword ascii /* score: '5.00'*/
      $s9 = "h%H%z` " fullword ascii /* score: '5.00'*/
      $s10 = "K+ qRi" fullword ascii /* score: '5.00'*/
      $s11 = "- 3f91" fullword ascii /* score: '5.00'*/
      $s12 = "T- H(c" fullword ascii /* score: '5.00'*/
      $s13 = "8Q-H* " fullword ascii /* score: '5.00'*/
      $s14 = "\\rRQN?" fullword ascii /* score: '5.00'*/
      $s15 = "Cz\"2- " fullword ascii /* score: '5.00'*/
      $s16 = "\\ qWhAIA_" fullword ascii /* score: '5.00'*/
      $s17 = "%TG%e2" fullword ascii /* score: '5.00'*/
      $s18 = "Vir* (" fullword ascii /* score: '5.00'*/
      $s19 = "JB,V%EQ%U" fullword ascii /* score: '5.00'*/
      $s20 = "{Q%f%O" fullword ascii /* score: '5.00'*/
      $s21 = "hg3%j%" fullword ascii /* score: '5.00'*/
      $s22 = ",.w- A" fullword ascii /* score: '5.00'*/
      $s23 = "%tk%}M" fullword ascii /* score: '5.00'*/
      $s24 = "SYfRVF7" fullword ascii /* score: '5.00'*/
      $s25 = "BAFPdc1" fullword ascii /* score: '5.00'*/
      $s26 = "\\Zqxb!" fullword ascii /* score: '5.00'*/
      $s27 = "wVPR@@-$" fullword ascii /* score: '4.00'*/
      $s28 = "`#fdhiS\\]" fullword ascii /* score: '4.00'*/
      $s29 = "ScXp8.(" fullword ascii /* score: '4.00'*/
      $s30 = "`IhIPpLu" fullword ascii /* score: '4.00'*/
      $s31 = "hBKd*Pg48u" fullword ascii /* score: '4.00'*/
      $s32 = "bPiE0MH" fullword ascii /* score: '4.00'*/
      $s33 = "eWQh\\yK" fullword ascii /* score: '4.00'*/
      $s34 = "SkbbwvSk" fullword ascii /* score: '4.00'*/
      $s35 = "zBWAh+[8" fullword ascii /* score: '4.00'*/
      $s36 = "wlHF%!u" fullword ascii /* score: '4.00'*/
      $s37 = "IGbB%\\" fullword ascii /* score: '4.00'*/
      $s38 = "h%UCoFh?I" fullword ascii /* score: '4.00'*/
      $s39 = "PCHhxIN" fullword ascii /* score: '4.00'*/
      $s40 = "jUir?9" fullword ascii /* score: '4.00'*/
      $s41 = "mfam\"1" fullword ascii /* score: '4.00'*/
      $s42 = "aAVjU9a_xI" fullword ascii /* score: '4.00'*/
      $s43 = "wQnI_:$Wv" fullword ascii /* score: '4.00'*/
      $s44 = "IqLct\"" fullword ascii /* score: '4.00'*/
      $s45 = ").hhr (#U" fullword ascii /* score: '4.00'*/
      $s46 = "wnjUs.p_!" fullword ascii /* score: '4.00'*/
      $s47 = "LlVOmXdG" fullword ascii /* score: '4.00'*/
      $s48 = "{dHEuP$H" fullword ascii /* score: '4.00'*/
      $s49 = "AyMdR5-" fullword ascii /* score: '4.00'*/
      $s50 = "2Qypz^hRv4" fullword ascii /* score: '4.00'*/
      $s51 = "Xhed!})E" fullword ascii /* score: '4.00'*/
      $s52 = "PQmX4!h" fullword ascii /* score: '4.00'*/
      $s53 = "tfZUV&@g" fullword ascii /* score: '4.00'*/
      $s54 = "xhxE)gc" fullword ascii /* score: '4.00'*/
      $s55 = "F[MoeP[]!'" fullword ascii /* score: '4.00'*/
      $s56 = "qdml*u'" fullword ascii /* score: '4.00'*/
      $s57 = ".teGy!" fullword ascii /* score: '4.00'*/
      $s58 = "&/.SeY" fullword ascii /* score: '4.00'*/
      $s59 = "jynRvzh" fullword ascii /* score: '4.00'*/
      $s60 = "B*.fFP+" fullword ascii /* score: '4.00'*/
      $s61 = "KQYIUyb" fullword ascii /* score: '4.00'*/
      $s62 = "Nclz[j1" fullword ascii /* score: '4.00'*/
      $s63 = "EDtUD\\!U" fullword ascii /* score: '4.00'*/
      $s64 = "dWgxLd>1@" fullword ascii /* score: '4.00'*/
      $s65 = "sKHKSn[" fullword ascii /* score: '4.00'*/
      $s66 = "bGVLu\"" fullword ascii /* score: '4.00'*/
      $s67 = "ydiU:e}" fullword ascii /* score: '4.00'*/
      $s68 = ".IEC%4" fullword ascii /* score: '4.00'*/
      $s69 = "oYPp\\j|" fullword ascii /* score: '4.00'*/
      $s70 = "uQoi2{B" fullword ascii /* score: '4.00'*/
      $s71 = "PBRqp\\N" fullword ascii /* score: '4.00'*/
      $s72 = "xaEL?+mk" fullword ascii /* score: '4.00'*/
      $s73 = "odKV)T^<" fullword ascii /* score: '4.00'*/
      $s74 = "tYRUBBW" fullword ascii /* score: '4.00'*/
      $s75 = "TKwl{H;" fullword ascii /* score: '4.00'*/
      $s76 = ")%s.J\\4" fullword ascii /* score: '4.00'*/
      $s77 = "PxvEf@s#\\" fullword ascii /* score: '4.00'*/
      $s78 = "urYi[ku" fullword ascii /* score: '4.00'*/
      $s79 = "3.xvJ<" fullword ascii /* score: '4.00'*/
      $s80 = "jKnXx F7" fullword ascii /* score: '4.00'*/
      $s81 = "PWXyQq_B" fullword ascii /* score: '4.00'*/
      $s82 = "$K}%d?" fullword ascii /* score: '4.00'*/
      $s83 = "jUseq[_\"" fullword ascii /* score: '4.00'*/
      $s84 = "HRXH\"VypN-" fullword ascii /* score: '4.00'*/
      $s85 = " teRTsr_n" fullword ascii /* score: '4.00'*/
      $s86 = "%:@]tPRu\"&1" fullword ascii /* score: '4.00'*/
      $s87 = "|LPxZ1hK{``" fullword ascii /* score: '4.00'*/
      $s88 = "eLyq|m," fullword ascii /* score: '4.00'*/
      $s89 = "JIAR03D" fullword ascii /* score: '4.00'*/
      $s90 = "^WQJE|\"" fullword ascii /* score: '4.00'*/
      $s91 = "Jbaf)7x" fullword ascii /* score: '4.00'*/
      $s92 = "]uo\\aqkXNjx9z" fullword ascii /* score: '4.00'*/
      $s93 = "StWBQYU" fullword ascii /* score: '4.00'*/
      $s94 = "sXzB3xz" fullword ascii /* score: '4.00'*/
      $s95 = "BHlKr?" fullword ascii /* score: '4.00'*/
      $s96 = "BvXRF^\"" fullword ascii /* score: '4.00'*/
      $s97 = "<XaHQ-QX" fullword ascii /* score: '4.00'*/
      $s98 = "wzPv3L<" fullword ascii /* score: '4.00'*/
      $s99 = "eOXpD\\" fullword ascii /* score: '4.00'*/
      $s100 = "dhbc]s|" fullword ascii /* score: '4.00'*/
      $s101 = ">${%tXKYWhc" fullword ascii /* score: '4.00'*/
      $s102 = "lgOGHCw" fullword ascii /* score: '4.00'*/
      $s103 = "SRQYZ_[" fullword ascii /* score: '4.00'*/
      $s104 = "LpDZKFs" fullword ascii /* score: '4.00'*/
      $s105 = "QXJqY\\l?" fullword ascii /* score: '4.00'*/
      $s106 = "WlVfrDt" fullword ascii /* score: '4.00'*/
      $s107 = "!wHNcv$D" fullword ascii /* score: '4.00'*/
      $s108 = "WVXl(]d" fullword ascii /* score: '4.00'*/
      $s109 = "PUhp3mL" fullword ascii /* score: '4.00'*/
      $s110 = "XPPVorP" fullword ascii /* score: '4.00'*/
      $s111 = "URvyER " fullword ascii /* score: '4.00'*/
      $s112 = "'ZRdC\\[" fullword ascii /* score: '4.00'*/
      $s113 = "WTAR}V3i" fullword ascii /* score: '4.00'*/
      $s114 = "ENFzX SK" fullword ascii /* score: '4.00'*/
      $s115 = "aEXVT.c" fullword ascii /* score: '4.00'*/
      $s116 = "PIiLp?" fullword ascii /* score: '4.00'*/
      $s117 = "1IGad/$l" fullword ascii /* score: '4.00'*/
      $s118 = ">utiQ4@+:" fullword ascii /* score: '4.00'*/
      $s119 = "HpMBh?" fullword ascii /* score: '4.00'*/
      $s120 = "V~RUagj.t" fullword ascii /* score: '4.00'*/
      $s121 = "uLLbfba" fullword ascii /* score: '4.00'*/
      $s122 = "uWsO?_" fullword ascii /* score: '4.00'*/
      $s123 = "WOgV-pH" fullword ascii /* score: '4.00'*/
      $s124 = "w+STBRW|$" fullword ascii /* score: '4.00'*/
      $s125 = "'^XlNVr`-" fullword ascii /* score: '4.00'*/
      $s126 = ":YTXi_)Pw{" fullword ascii /* score: '4.00'*/
      $s127 = "pFBCF+u2" fullword ascii /* score: '4.00'*/
      $s128 = "vZMcty\\" fullword ascii /* score: '4.00'*/
      $s129 = "KXVSA(*" fullword ascii /* score: '4.00'*/
      $s130 = "wLONQ0P" fullword ascii /* score: '4.00'*/
      $s131 = "KuAdD|Lx" fullword ascii /* score: '4.00'*/
      $s132 = "WvCQU#B{" fullword ascii /* score: '4.00'*/
      $s133 = "btpx\"@4(" fullword ascii /* score: '4.00'*/
      $s134 = "h'HMQq<'p" fullword ascii /* score: '4.00'*/
      $s135 = "@jtgx14v" fullword ascii /* score: '4.00'*/
      $s136 = "mQwHScN" fullword ascii /* score: '4.00'*/
      $s137 = "EviB3>q." fullword ascii /* score: '4.00'*/
      $s138 = "opnrO\"" fullword ascii /* score: '4.00'*/
      $s139 = "tXMvd(kH" fullword ascii /* score: '4.00'*/
      $s140 = "JeBN>% " fullword ascii /* score: '4.00'*/
      $s141 = "jfkw\"m" fullword ascii /* score: '4.00'*/
      $s142 = "CcWhs\"/sQ" fullword ascii /* score: '4.00'*/
      $s143 = "TTYU? " fullword ascii /* score: '4.00'*/
      $s144 = "LQLPCK" fullword ascii /* score: '3.50'*/
      $s145 = "t mjkf" fullword ascii /* score: '3.00'*/
      $s146 = "\\7ZtCX" fullword ascii /* score: '2.00'*/
      $s147 = "\\\\eLRU" fullword ascii /* score: '2.00'*/
      $s148 = "pLLMY6" fullword ascii /* score: '2.00'*/
      $s149 = "\\<%[oa" fullword ascii /* score: '2.00'*/
      $s150 = "\\3Y)>Rj" fullword ascii /* score: '2.00'*/
      $s151 = "osTH03" fullword ascii /* score: '2.00'*/
      $s152 = "\\J%}:T_" fullword ascii /* score: '2.00'*/
      $s153 = "ACMfX3" fullword ascii /* score: '2.00'*/
      $s154 = "\\G`>79i" fullword ascii /* score: '2.00'*/
      $s155 = "\\Y]d(1" fullword ascii /* score: '2.00'*/
      $s156 = "\\:sHbt" fullword ascii /* score: '2.00'*/
      $s157 = "\\t6?F2" fullword ascii /* score: '2.00'*/
      $s158 = "\\{!)1T" fullword ascii /* score: '2.00'*/
      $s159 = "\\q@y=%" fullword ascii /* score: '2.00'*/
      $s160 = "\\RW:GB" fullword ascii /* score: '2.00'*/
      $s161 = "\\_\\EDs" fullword ascii /* score: '2.00'*/
      $s162 = "\\%MCw*" fullword ascii /* score: '2.00'*/
      $s163 = "\\7IDg8F" fullword ascii /* score: '2.00'*/
      $s164 = "\\ T?P,t:" fullword ascii /* score: '2.00'*/
      $s165 = "WqqKU0" fullword ascii /* score: '2.00'*/
      $s166 = "\\b`Ky " fullword ascii /* score: '2.00'*/
      $s167 = "tXiXv8" fullword ascii /* score: '2.00'*/
      $s168 = "\\W.iT7" fullword ascii /* score: '2.00'*/
      $s169 = "\\.kw @" fullword ascii /* score: '2.00'*/
      $s170 = "\\HJd3h_" fullword ascii /* score: '2.00'*/
      $s171 = "\\iFz'(" fullword ascii /* score: '2.00'*/
      $s172 = "\\,/YLe=" fullword ascii /* score: '2.00'*/
      $s173 = "wqaB39" fullword ascii /* score: '2.00'*/
      $s174 = "\\W%pD$" fullword ascii /* score: '2.00'*/
      $s175 = "\\]~_N<(" fullword ascii /* score: '2.00'*/
      $s176 = "MrXB40" fullword ascii /* score: '2.00'*/
      $s177 = "\\$B?t&" fullword ascii /* score: '2.00'*/
      $s178 = "\\Z6k6v" fullword ascii /* score: '2.00'*/
      $s179 = "\\Q0txAx" fullword ascii /* score: '2.00'*/
      $s180 = "kHdbN7" fullword ascii /* score: '2.00'*/
      $s181 = "\\ Vd'S" fullword ascii /* score: '2.00'*/
      $s182 = "\\.Lxi1C" fullword ascii /* score: '2.00'*/
      $s183 = "\\3_tq:" fullword ascii /* score: '2.00'*/
      $s184 = "\\$k|FiQ" fullword ascii /* score: '2.00'*/
      $s185 = "\\[d'N1%:" fullword ascii /* score: '2.00'*/
      $s186 = "ubKrs0" fullword ascii /* score: '2.00'*/
      $s187 = "|A\\u.3t" fullword ascii /* score: '1.00'*/
      $s188 = "2X0SLX" fullword ascii /* score: '1.00'*/
      $s189 = "QcJ4lZ" fullword ascii /* score: '1.00'*/
      $s190 = "|%7^BPH" fullword ascii /* score: '1.00'*/
      $s191 = "5iN[X/]" fullword ascii /* score: '1.00'*/
      $s192 = "i]y*I{" fullword ascii /* score: '1.00'*/
      $s193 = "Xa^%z]5" fullword ascii /* score: '1.00'*/
      $s194 = "iUPuO<" fullword ascii /* score: '1.00'*/
      $s195 = "*QfXI-" fullword ascii /* score: '1.00'*/
      $s196 = "0 3=Ik" fullword ascii /* score: '1.00'*/
      $s197 = "`+jW7g" fullword ascii /* score: '1.00'*/
      $s198 = "s%otI?" fullword ascii /* score: '1.00'*/
      $s199 = "n'NoCK" fullword ascii /* score: '1.00'*/
      $s200 = "u!X#H,br" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule ee170a14d676b69cab768f8a94e482ee9ad6dc1766038d6e26c24fe2cfbd7677 {
   meta:
      description = "Amadey_MALW - file ee170a14d676b69cab768f8a94e482ee9ad6dc1766038d6e26c24fe2cfbd7677"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "ee170a14d676b69cab768f8a94e482ee9ad6dc1766038d6e26c24fe2cfbd7677"
   strings:
      $s1 = "USER32.dql" fullword ascii /* score: '13.00'*/
      $s2 = "+,4.`+1{\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'A' */
      $s3 = "etmksbbt" fullword ascii /* score: '8.00'*/
      $s4 = "iosnleeh" fullword ascii /* score: '8.00'*/
      $s5 = "nn:\"~T" fullword ascii /* score: '7.00'*/
      $s6 = "\\3EYe`" fullword ascii /* score: '7.00'*/
      $s7 = ";<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s8 = "D5W:\"(" fullword ascii /* score: '7.00'*/
      $s9 = "PQRSUVW" fullword ascii /* score: '6.50'*/
      $s10 = "'Irc^R" fullword ascii /* score: '6.00'*/
      $s11 = "%tu /h" fullword ascii /* score: '5.00'*/
      $s12 = "sO?& /Pf)m" fullword ascii /* score: '5.00'*/
      $s13 = "G]x -+" fullword ascii /* score: '5.00'*/
      $s14 = "M~19y* " fullword ascii /* score: '5.00'*/
      $s15 = "Z -)01" fullword ascii /* score: '5.00'*/
      $s16 = "MI%f%~i" fullword ascii /* score: '5.00'*/
      $s17 = "# B4:T" fullword ascii /* score: '5.00'*/
      $s18 = "x$%R* 4?" fullword ascii /* score: '5.00'*/
      $s19 = "Eh- yf" fullword ascii /* score: '5.00'*/
      $s20 = "VCkywb3" fullword ascii /* score: '5.00'*/
      $s21 = "1 -(z8" fullword ascii /* score: '5.00'*/
      $s22 = "d*- $JQ" fullword ascii /* score: '5.00'*/
      $s23 = "l?8k7* _" fullword ascii /* score: '5.00'*/
      $s24 = "JF$x\"* " fullword ascii /* score: '5.00'*/
      $s25 = "+ ;bhp^" fullword ascii /* score: '5.00'*/
      $s26 = "F*  _0" fullword ascii /* score: '5.00'*/
      $s27 = "tAaAH\"`" fullword ascii /* score: '4.00'*/
      $s28 = "ZbLB|ul" fullword ascii /* score: '4.00'*/
      $s29 = ";~nQpI8z@" fullword ascii /* score: '4.00'*/
      $s30 = "bdtEB!" fullword ascii /* score: '4.00'*/
      $s31 = "vUTU,Jo" fullword ascii /* score: '4.00'*/
      $s32 = "voRus-$" fullword ascii /* score: '4.00'*/
      $s33 = "3x.XXO/" fullword ascii /* score: '4.00'*/
      $s34 = "dUVnyQR" fullword ascii /* score: '4.00'*/
      $s35 = "YBAka_MO" fullword ascii /* score: '4.00'*/
      $s36 = "pULz>ZZ" fullword ascii /* score: '4.00'*/
      $s37 = "ZXop!U" fullword ascii /* score: '4.00'*/
      $s38 = "ahRk(:!N>" fullword ascii /* score: '4.00'*/
      $s39 = "HtUVINd" fullword ascii /* score: '4.00'*/
      $s40 = "jOhk9@3" fullword ascii /* score: '4.00'*/
      $s41 = "AshpKf," fullword ascii /* score: '4.00'*/
      $s42 = "|lMtkmHD|" fullword ascii /* score: '4.00'*/
      $s43 = "tXgLL<L$:|" fullword ascii /* score: '4.00'*/
      $s44 = "FeKaozm" fullword ascii /* score: '4.00'*/
      $s45 = ")vJcMP[uq" fullword ascii /* score: '4.00'*/
      $s46 = "0jAeSH&eJ" fullword ascii /* score: '4.00'*/
      $s47 = "P-%D&b" fullword ascii /* score: '4.00'*/
      $s48 = "gAZHV0|" fullword ascii /* score: '4.00'*/
      $s49 = "5saFz-#l" fullword ascii /* score: '4.00'*/
      $s50 = "v:RjTqDIu" fullword ascii /* score: '4.00'*/
      $s51 = "apaJ\"(" fullword ascii /* score: '4.00'*/
      $s52 = "JbMgci<" fullword ascii /* score: '4.00'*/
      $s53 = "kKfT 4qHj" fullword ascii /* score: '4.00'*/
      $s54 = "XhuNO9Ul" fullword ascii /* score: '4.00'*/
      $s55 = "WvPZ\" !" fullword ascii /* score: '4.00'*/
      $s56 = "EUyRo+-U" fullword ascii /* score: '4.00'*/
      $s57 = "WeaGXWT>" fullword ascii /* score: '4.00'*/
      $s58 = "ATBPkILwtP?" fullword ascii /* score: '4.00'*/
      $s59 = "IsGp%(v@" fullword ascii /* score: '4.00'*/
      $s60 = "aWPR@+ZXy`w_5" fullword ascii /* score: '4.00'*/
      $s61 = "sIpIw{h" fullword ascii /* score: '4.00'*/
      $s62 = "bJMH\"(" fullword ascii /* score: '4.00'*/
      $s63 = "ZmXy.&E" fullword ascii /* score: '4.00'*/
      $s64 = "KcJg,49" fullword ascii /* score: '4.00'*/
      $s65 = "oFXXH<H" fullword ascii /* score: '4.00'*/
      $s66 = "RfOQ2//" fullword ascii /* score: '4.00'*/
      $s67 = "GrSk%WF" fullword ascii /* score: '4.00'*/
      $s68 = "{|qEyZEILv|1x" fullword ascii /* score: '4.00'*/
      $s69 = "sXkn\\!" fullword ascii /* score: '4.00'*/
      $s70 = ".SLr?_e;" fullword ascii /* score: '4.00'*/
      $s71 = "KVdO5.{?" fullword ascii /* score: '4.00'*/
      $s72 = "0saPIMe." fullword ascii /* score: '4.00'*/
      $s73 = "ThbHKw`l" fullword ascii /* score: '4.00'*/
      $s74 = "%'qbcwqmY4>" fullword ascii /* score: '4.00'*/
      $s75 = "LyFLLMT" fullword ascii /* score: '4.00'*/
      $s76 = "ZPWX_G1" fullword ascii /* score: '4.00'*/
      $s77 = "qmxQ!L" fullword ascii /* score: '4.00'*/
      $s78 = "QqiW19(*8D" fullword ascii /* score: '4.00'*/
      $s79 = "]v-XULi/]Q\\" fullword ascii /* score: '4.00'*/
      $s80 = "q(IDyd!" fullword ascii /* score: '4.00'*/
      $s81 = "mGLdx8|" fullword ascii /* score: '4.00'*/
      $s82 = "]OiwJP,~" fullword ascii /* score: '4.00'*/
      $s83 = "8mUTK]glha" fullword ascii /* score: '4.00'*/
      $s84 = "UyRJ$eI" fullword ascii /* score: '4.00'*/
      $s85 = "ZWec,[4z" fullword ascii /* score: '4.00'*/
      $s86 = "tzitB/q9q" fullword ascii /* score: '4.00'*/
      $s87 = "jjfP=$$9e><" fullword ascii /* score: '4.00'*/
      $s88 = "yVNkb1Vj" fullword ascii /* score: '4.00'*/
      $s89 = "cUgf0<j" fullword ascii /* score: '4.00'*/
      $s90 = "sJMz c:" fullword ascii /* score: '4.00'*/
      $s91 = "NElnV{e" fullword ascii /* score: '4.00'*/
      $s92 = "Uafv$F/\"2" fullword ascii /* score: '4.00'*/
      $s93 = "(HuHH:8(" fullword ascii /* score: '4.00'*/
      $s94 = "ZX.OPP,," fullword ascii /* score: '4.00'*/
      $s95 = "BQYep!" fullword ascii /* score: '4.00'*/
      $s96 = "PXma8@+" fullword ascii /* score: '4.00'*/
      $s97 = "KXdNR:}" fullword ascii /* score: '4.00'*/
      $s98 = "ZWdC$)*" fullword ascii /* score: '4.00'*/
      $s99 = ")KwbrQ|I)-" fullword ascii /* score: '4.00'*/
      $s100 = "UPWa=T+" fullword ascii /* score: '4.00'*/
      $s101 = "vVSW=h?" fullword ascii /* score: '4.00'*/
      $s102 = "kwDD[?w" fullword ascii /* score: '4.00'*/
      $s103 = "AbVs-M;" fullword ascii /* score: '4.00'*/
      $s104 = "kvbZB=B" fullword ascii /* score: '4.00'*/
      $s105 = "8FntH09pW" fullword ascii /* score: '4.00'*/
      $s106 = "YhpDI~>8p\\" fullword ascii /* score: '4.00'*/
      $s107 = "BiFn+6Ua" fullword ascii /* score: '4.00'*/
      $s108 = "qEURuT F4" fullword ascii /* score: '4.00'*/
      $s109 = "BnhFAMm\\" fullword ascii /* score: '4.00'*/
      $s110 = "UeUE(Kug" fullword ascii /* score: '4.00'*/
      $s111 = "QbIBzq iY}" fullword ascii /* score: '4.00'*/
      $s112 = "hgJgp/u`" fullword ascii /* score: '4.00'*/
      $s113 = "szpA\"a" fullword ascii /* score: '4.00'*/
      $s114 = "YUnb?]Jh" fullword ascii /* score: '4.00'*/
      $s115 = "hLsWXnx" fullword ascii /* score: '4.00'*/
      $s116 = "-gaHkt!" fullword ascii /* score: '4.00'*/
      $s117 = "^Zg.kWm" fullword ascii /* score: '4.00'*/
      $s118 = "mkmW\"nq`" fullword ascii /* score: '4.00'*/
      $s119 = "g>BCqu!," fullword ascii /* score: '4.00'*/
      $s120 = "LoBL!N" fullword ascii /* score: '4.00'*/
      $s121 = "QwyZ/dy" fullword ascii /* score: '4.00'*/
      $s122 = "aXqj s[" fullword ascii /* score: '4.00'*/
      $s123 = "lJcm)vL" fullword ascii /* score: '4.00'*/
      $s124 = "wVHA^)|" fullword ascii /* score: '4.00'*/
      $s125 = "K.ukxD?" fullword ascii /* score: '4.00'*/
      $s126 = "G!lPxc!" fullword ascii /* score: '4.00'*/
      $s127 = "HyNC XZY" fullword ascii /* score: '4.00'*/
      $s128 = "pUYaIgv" fullword ascii /* score: '4.00'*/
      $s129 = "fhyn1@r" fullword ascii /* score: '4.00'*/
      $s130 = "--.WVd" fullword ascii /* score: '4.00'*/
      $s131 = "EqTWhC@5" fullword ascii /* score: '4.00'*/
      $s132 = "I%hTWK+j0" fullword ascii /* score: '4.00'*/
      $s133 = ".Fjm:E\\" fullword ascii /* score: '4.00'*/
      $s134 = "qQJQ$^'W" fullword ascii /* score: '4.00'*/
      $s135 = "OUTpPro" fullword ascii /* score: '4.00'*/
      $s136 = ".jnP~4" fullword ascii /* score: '4.00'*/
      $s137 = "WQNITuk" fullword ascii /* score: '4.00'*/
      $s138 = "tGYzw(+" fullword ascii /* score: '4.00'*/
      $s139 = "kWBdb-^" fullword ascii /* score: '4.00'*/
      $s140 = "EplP$QzP" fullword ascii /* score: '4.00'*/
      $s141 = "QQitr2d" fullword ascii /* score: '4.00'*/
      $s142 = "JeIN?-" fullword ascii /* score: '4.00'*/
      $s143 = " ldAD!" fullword ascii /* score: '4.00'*/
      $s144 = "nWEL?s" fullword ascii /* score: '4.00'*/
      $s145 = "utKy.EF" fullword ascii /* score: '4.00'*/
      $s146 = "WWsOr^Bt" fullword ascii /* score: '4.00'*/
      $s147 = "%z,]1K" fullword ascii /* score: '3.50'*/
      $s148 = "RWTCSJ" fullword ascii /* score: '3.50'*/
      $s149 = "F@Db%t-" fullword ascii /* score: '3.50'*/
      $s150 = "%a1%v,p@" fullword ascii /* score: '3.50'*/
      $s151 = "NIDYGW" fullword ascii /* score: '3.50'*/
      $s152 = "Dlawhc" fullword ascii /* score: '3.00'*/
      $s153 = "ZAPSX2" fullword ascii /* score: '2.00'*/
      $s154 = "\\E}Wb9" fullword ascii /* score: '2.00'*/
      $s155 = "\\Cd x)J`$" fullword ascii /* score: '2.00'*/
      $s156 = "\\-3)KH" fullword ascii /* score: '2.00'*/
      $s157 = "\\ui7F`" fullword ascii /* score: '2.00'*/
      $s158 = "\\:1r>N" fullword ascii /* score: '2.00'*/
      $s159 = "\\e@X8Y8" fullword ascii /* score: '2.00'*/
      $s160 = "\\4zufyJ" fullword ascii /* score: '2.00'*/
      $s161 = "\\+M>{H" fullword ascii /* score: '2.00'*/
      $s162 = "dsYtB8" fullword ascii /* score: '2.00'*/
      $s163 = "\\9KrR(" fullword ascii /* score: '2.00'*/
      $s164 = "vflPH2" fullword ascii /* score: '2.00'*/
      $s165 = "bqcuP7" fullword ascii /* score: '2.00'*/
      $s166 = "vkpAJ8" fullword ascii /* score: '2.00'*/
      $s167 = "\\K.h;V" fullword ascii /* score: '2.00'*/
      $s168 = "\\XLE:WA" fullword ascii /* score: '2.00'*/
      $s169 = "\\0B`,I " fullword ascii /* score: '2.00'*/
      $s170 = "wQeIu1" fullword ascii /* score: '2.00'*/
      $s171 = "\\1F4kI" fullword ascii /* score: '2.00'*/
      $s172 = "\\\"3B*y#" fullword ascii /* score: '2.00'*/
      $s173 = "hybDq4" fullword ascii /* score: '2.00'*/
      $s174 = "\\.b ?j" fullword ascii /* score: '2.00'*/
      $s175 = "\\o{W$&" fullword ascii /* score: '2.00'*/
      $s176 = "\\x,a\\I" fullword ascii /* score: '2.00'*/
      $s177 = "\\!}.qJ" fullword ascii /* score: '2.00'*/
      $s178 = "qpIqa5" fullword ascii /* score: '2.00'*/
      $s179 = "\\(87P*" fullword ascii /* score: '2.00'*/
      $s180 = "\\`#d`1" fullword ascii /* score: '2.00'*/
      $s181 = "\\K-v2Q5R," fullword ascii /* score: '2.00'*/
      $s182 = "\\#X|a-9p." fullword ascii /* score: '2.00'*/
      $s183 = "\\\"Jzp F" fullword ascii /* score: '2.00'*/
      $s184 = "\\NDr.!" fullword ascii /* score: '2.00'*/
      $s185 = "\\2do!N" fullword ascii /* score: '2.00'*/
      $s186 = "NVDUG7" fullword ascii /* score: '2.00'*/
      $s187 = "WQQid4" fullword ascii /* score: '2.00'*/
      $s188 = "APTXW9" fullword ascii /* score: '2.00'*/
      $s189 = "UfuJ74" fullword ascii /* score: '2.00'*/
      $s190 = "\\#qwhR~" fullword ascii /* score: '2.00'*/
      $s191 = "\\?dP B" fullword ascii /* score: '2.00'*/
      $s192 = "vzQoz2" fullword ascii /* score: '2.00'*/
      $s193 = "\\TnI6WL" fullword ascii /* score: '2.00'*/
      $s194 = "nCTRL+" fullword ascii /* score: '1.00'*/
      $s195 = "{s4wi4Y" fullword ascii /* score: '1.00'*/
      $s196 = "_^][ZY" fullword ascii /* score: '1.00'*/
      $s197 = "^][ZYX" fullword ascii /* score: '1.00'*/
      $s198 = "IR!-{tr0" fullword ascii /* score: '1.00'*/
      $s199 = "O\"yu\\_" fullword ascii /* score: '1.00'*/
      $s200 = "(yvIwn5" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule sig_7d05ae98fea42630b199a45f26e18a7196a8f3509ed703fc918416780fd1f661 {
   meta:
      description = "Amadey_MALW - file 7d05ae98fea42630b199a45f26e18a7196a8f3509ed703fc918416780fd1f661"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "7d05ae98fea42630b199a45f26e18a7196a8f3509ed703fc918416780fd1f661"
   strings:
      $s1 = "sxdezqxh" fullword ascii /* score: '8.00'*/
      $s2 = "bzkmssua" fullword ascii /* score: '8.00'*/
      $s3 = "d6h6l6p6<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s4 = ")0DlLq" fullword ascii /* score: '6.00'*/
      $s5 = "Q7IRC0" fullword ascii /* score: '6.00'*/
      $s6 = "oA9 -;B" fullword ascii /* score: '5.00'*/
      $s7 = "_ t+Xex$- " fullword ascii /* score: '5.00'*/
      $s8 = "' f+ V/ F4 " fullword ascii /* score: '5.00'*/
      $s9 = "ADVePI1" fullword ascii /* score: '5.00'*/
      $s10 = "%WEf%0" fullword ascii /* score: '5.00'*/
      $s11 = "ER1x- lh" fullword ascii /* score: '5.00'*/
      $s12 = "YZu~ -Ev" fullword ascii /* score: '5.00'*/
      $s13 = "tk- )@" fullword ascii /* score: '5.00'*/
      $s14 = "1;5O -" fullword ascii /* score: '5.00'*/
      $s15 = "`c+ R%P h" fullword ascii /* score: '5.00'*/
      $s16 = "7TfJ(* " fullword ascii /* score: '5.00'*/
      $s17 = "+ l2H:" fullword ascii /* score: '5.00'*/
      $s18 = "nSCMa^Og'rA" fullword ascii /* score: '4.00'*/
      $s19 = "KNff6(=" fullword ascii /* score: '4.00'*/
      $s20 = "@2^xxic_P$" fullword ascii /* score: '4.00'*/
      $s21 = "RZlChYd" fullword ascii /* score: '4.00'*/
      $s22 = "v_TqrvZB+" fullword ascii /* score: '4.00'*/
      $s23 = "PpxdNlq" fullword ascii /* score: '4.00'*/
      $s24 = "VRar5Al" fullword ascii /* score: '4.00'*/
      $s25 = "ItXq|&oc" fullword ascii /* score: '4.00'*/
      $s26 = "4@mo$%S4" fullword ascii /* score: '4.00'*/
      $s27 = "vYHC}Pr" fullword ascii /* score: '4.00'*/
      $s28 = "VTSg?%" fullword ascii /* score: '4.00'*/
      $s29 = "pXOl>\"89" fullword ascii /* score: '4.00'*/
      $s30 = "lshc/@Y" fullword ascii /* score: '4.00'*/
      $s31 = "XISG-wL" fullword ascii /* score: '4.00'*/
      $s32 = "@YoMP]+k" fullword ascii /* score: '4.00'*/
      $s33 = "SUvjB\\" fullword ascii /* score: '4.00'*/
      $s34 = "JevO)!if:" fullword ascii /* score: '4.00'*/
      $s35 = "P*QvEK` kC" fullword ascii /* score: '4.00'*/
      $s36 = "yqIfV7)" fullword ascii /* score: '4.00'*/
      $s37 = "lbYs$I*l" fullword ascii /* score: '4.00'*/
      $s38 = "[2PCnlv+R" fullword ascii /* score: '4.00'*/
      $s39 = "kfAy#$(" fullword ascii /* score: '4.00'*/
      $s40 = "XMeX4?L" fullword ascii /* score: '4.00'*/
      $s41 = "iqDz\\0x" fullword ascii /* score: '4.00'*/
      $s42 = "IVIKWM`" fullword ascii /* score: '4.00'*/
      $s43 = "Vx.gSS" fullword ascii /* score: '4.00'*/
      $s44 = "1USER32" fullword ascii /* score: '4.00'*/
      $s45 = "vnXd9o," fullword ascii /* score: '4.00'*/
      $s46 = ",/FPIPAv_" fullword ascii /* score: '4.00'*/
      $s47 = "HZKry /" fullword ascii /* score: '4.00'*/
      $s48 = "beBKN1wd" fullword ascii /* score: '4.00'*/
      $s49 = ">QTKouKK" fullword ascii /* score: '4.00'*/
      $s50 = "`RhgLXcd2HQ" fullword ascii /* score: '4.00'*/
      $s51 = "FOKN2 @" fullword ascii /* score: '4.00'*/
      $s52 = "YFDD*\\R0" fullword ascii /* score: '4.00'*/
      $s53 = "HAbe _XPl" fullword ascii /* score: '4.00'*/
      $s54 = "/THDd`(8#{" fullword ascii /* score: '4.00'*/
      $s55 = "aUZY)@(" fullword ascii /* score: '4.00'*/
      $s56 = "/pIqz<u " fullword ascii /* score: '4.00'*/
      $s57 = ":p.gAd" fullword ascii /* score: '4.00'*/
      $s58 = "ZwVvGXt" fullword ascii /* score: '4.00'*/
      $s59 = "kXrT[[HI%" fullword ascii /* score: '4.00'*/
      $s60 = "GISyK0k" fullword ascii /* score: '4.00'*/
      $s61 = "uKJgI[v" fullword ascii /* score: '4.00'*/
      $s62 = "IwSP-@," fullword ascii /* score: '4.00'*/
      $s63 = "3rbQwVIX" fullword ascii /* score: '4.00'*/
      $s64 = ".Ewq<." fullword ascii /* score: '4.00'*/
      $s65 = "@ntudJV0" fullword ascii /* score: '4.00'*/
      $s66 = "RIdn$+1" fullword ascii /* score: '4.00'*/
      $s67 = "BRtlA.oo/a" fullword ascii /* score: '4.00'*/
      $s68 = "BWIz`%{" fullword ascii /* score: '4.00'*/
      $s69 = "IWzs4?y" fullword ascii /* score: '4.00'*/
      $s70 = "Vvzu[I%|" fullword ascii /* score: '4.00'*/
      $s71 = "8KwSUBc`" fullword ascii /* score: '4.00'*/
      $s72 = "bhpbc!m" fullword ascii /* score: '4.00'*/
      $s73 = "NpHk!X" fullword ascii /* score: '4.00'*/
      $s74 = "+PJma1F}" fullword ascii /* score: '4.00'*/
      $s75 = "JVERV<i" fullword ascii /* score: '4.00'*/
      $s76 = "&8IIky!]" fullword ascii /* score: '4.00'*/
      $s77 = "QUYP`g$;:" fullword ascii /* score: '4.00'*/
      $s78 = "S}xhXDu(R" fullword ascii /* score: '4.00'*/
      $s79 = "zpKtiK~" fullword ascii /* score: '4.00'*/
      $s80 = "[2nDOJR0:t" fullword ascii /* score: '4.00'*/
      $s81 = "+2.lSf" fullword ascii /* score: '4.00'*/
      $s82 = "jkRp?i" fullword ascii /* score: '4.00'*/
      $s83 = "Aakihi/" fullword ascii /* score: '4.00'*/
      $s84 = "EGPHX/]" fullword ascii /* score: '4.00'*/
      $s85 = "kQEc4q30" fullword ascii /* score: '4.00'*/
      $s86 = "iWXn^;uL" fullword ascii /* score: '4.00'*/
      $s87 = "GPLERa\"" fullword ascii /* score: '4.00'*/
      $s88 = "RtDi]Z0" fullword ascii /* score: '4.00'*/
      $s89 = "HsaE(z|" fullword ascii /* score: '4.00'*/
      $s90 = "oEjS%^_EZ" fullword ascii /* score: '4.00'*/
      $s91 = "npXbIC'\"-t" fullword ascii /* score: '4.00'*/
      $s92 = "vVSTuxp" fullword ascii /* score: '4.00'*/
      $s93 = "VRaYtJt" fullword ascii /* score: '4.00'*/
      $s94 = "pPhV!4" fullword ascii /* score: '4.00'*/
      $s95 = "l7DrJSDp\"q" fullword ascii /* score: '4.00'*/
      $s96 = "QqXrs82![" fullword ascii /* score: '4.00'*/
      $s97 = "vZFJT$E" fullword ascii /* score: '4.00'*/
      $s98 = "TtRWIdVxe" fullword ascii /* score: '4.00'*/
      $s99 = "9%S5:/" fullword ascii /* score: '4.00'*/
      $s100 = "tjhVD\"-Z" fullword ascii /* score: '4.00'*/
      $s101 = "KLcX3|[" fullword ascii /* score: '4.00'*/
      $s102 = "<JFdZc-." fullword ascii /* score: '4.00'*/
      $s103 = "qHPdtpTD" fullword ascii /* score: '4.00'*/
      $s104 = "%FrVKQ2zd" fullword ascii /* score: '4.00'*/
      $s105 = "mfIg!8" fullword ascii /* score: '4.00'*/
      $s106 = "ZONpC&t" fullword ascii /* score: '4.00'*/
      $s107 = "PTWQ\\;" fullword ascii /* score: '4.00'*/
      $s108 = "PLtw|7`" fullword ascii /* score: '4.00'*/
      $s109 = ";qFIu{`?" fullword ascii /* score: '4.00'*/
      $s110 = "{U{fzXF365^" fullword ascii /* score: '4.00'*/
      $s111 = "q(gUTL\"%]" fullword ascii /* score: '4.00'*/
      $s112 = "xliH!F" fullword ascii /* score: '4.00'*/
      $s113 = "Jl('.VEx" fullword ascii /* score: '4.00'*/
      $s114 = "P-UhLjH],K4#" fullword ascii /* score: '4.00'*/
      $s115 = "XQhD)lX" fullword ascii /* score: '4.00'*/
      $s116 = "iNIAt!M9" fullword ascii /* score: '4.00'*/
      $s117 = "sbQI:*^" fullword ascii /* score: '4.00'*/
      $s118 = "QXJREgBW%q)" fullword ascii /* score: '4.00'*/
      $s119 = "Kugx5\\" fullword ascii /* score: '4.00'*/
      $s120 = "NlUl;&7" fullword ascii /* score: '4.00'*/
      $s121 = "wBYGD?" fullword ascii /* score: '4.00'*/
      $s122 = "mHYXB<k" fullword ascii /* score: '4.00'*/
      $s123 = "eiBQ0n+2" fullword ascii /* score: '4.00'*/
      $s124 = "NYrHWBB" fullword ascii /* score: '4.00'*/
      $s125 = "UiNVtrH" fullword ascii /* score: '4.00'*/
      $s126 = "PLnas*>Y" fullword ascii /* score: '4.00'*/
      $s127 = "fBRJF?" fullword ascii /* score: '4.00'*/
      $s128 = "!iWIU!/" fullword ascii /* score: '4.00'*/
      $s129 = "R3-aYtD3|]" fullword ascii /* score: '4.00'*/
      $s130 = "nAYX. 9" fullword ascii /* score: '4.00'*/
      $s131 = ".vpDG?p`}" fullword ascii /* score: '4.00'*/
      $s132 = "ZczeH0DxXa" fullword ascii /* score: '4.00'*/
      $s133 = "-WoxOVAurX4;" fullword ascii /* score: '4.00'*/
      $s134 = "z@UXKG85AV(Dt" fullword ascii /* score: '4.00'*/
      $s135 = "VYaRtJt" fullword ascii /* score: '4.00'*/
      $s136 = "+FSXq,$~" fullword ascii /* score: '4.00'*/
      $s137 = "WyJiT;i" fullword ascii /* score: '4.00'*/
      $s138 = "ixAdWlDeI" fullword ascii /* score: '4.00'*/
      $s139 = "XPzzv8u@" fullword ascii /* score: '4.00'*/
      $s140 = "JbBPCc$" fullword ascii /* score: '4.00'*/
      $s141 = "veRvS-g" fullword ascii /* score: '4.00'*/
      $s142 = "QKIu2cuF" fullword ascii /* score: '4.00'*/
      $s143 = "Hdhs'@{" fullword ascii /* score: '4.00'*/
      $s144 = "thgA\\(G=" fullword ascii /* score: '4.00'*/
      $s145 = "6qViKX~@" fullword ascii /* score: '4.00'*/
      $s146 = "$Y5%v:,K/4" fullword ascii /* score: '3.50'*/
      $s147 = "MQJITH" fullword ascii /* score: '3.50'*/
      $s148 = "$`%g-\\_p" fullword ascii /* score: '3.50'*/
      $s149 = "r/A:\"\\" fullword ascii /* score: '3.00'*/
      $s150 = "\\$vtRU(" fullword ascii /* score: '2.00'*/
      $s151 = "\\PY&Y=" fullword ascii /* score: '2.00'*/
      $s152 = "yxcVi5" fullword ascii /* score: '2.00'*/
      $s153 = "\\))@\"&" fullword ascii /* score: '2.00'*/
      $s154 = "\\i0If-" fullword ascii /* score: '2.00'*/
      $s155 = "\\ZB c+" fullword ascii /* score: '2.00'*/
      $s156 = "\\8$_--;" fullword ascii /* score: '2.00'*/
      $s157 = "vqlB19" fullword ascii /* score: '2.00'*/
      $s158 = "\\7Hl`zb" fullword ascii /* score: '2.00'*/
      $s159 = "\\-V@XU" fullword ascii /* score: '2.00'*/
      $s160 = "\\(B ,Q3" fullword ascii /* score: '2.00'*/
      $s161 = "\\S_umK=" fullword ascii /* score: '2.00'*/
      $s162 = "\\aZc7N)" fullword ascii /* score: '2.00'*/
      $s163 = "\\|]^Z`" fullword ascii /* score: '2.00'*/
      $s164 = "\\{%\\#h" fullword ascii /* score: '2.00'*/
      $s165 = "\\F{/WQ" fullword ascii /* score: '2.00'*/
      $s166 = "qIkq10" fullword ascii /* score: '2.00'*/
      $s167 = "\\$EAxAs" fullword ascii /* score: '2.00'*/
      $s168 = "\\yX{00" fullword ascii /* score: '2.00'*/
      $s169 = "\\&IW3`2OT" fullword ascii /* score: '2.00'*/
      $s170 = "\\J%)VY5XU" fullword ascii /* score: '2.00'*/
      $s171 = "DWwnp8" fullword ascii /* score: '2.00'*/
      $s172 = "\\8rUq/" fullword ascii /* score: '2.00'*/
      $s173 = "\\l%aG9q+" fullword ascii /* score: '2.00'*/
      $s174 = "\\Hb<I<" fullword ascii /* score: '2.00'*/
      $s175 = "\\^sphe" fullword ascii /* score: '2.00'*/
      $s176 = "\\*XY?(" fullword ascii /* score: '2.00'*/
      $s177 = "\\k!c-$sP" fullword ascii /* score: '2.00'*/
      $s178 = "\\C|,/," fullword ascii /* score: '2.00'*/
      $s179 = "\\:JP@((" fullword ascii /* score: '2.00'*/
      $s180 = "\\KEHMQ" fullword ascii /* score: '2.00'*/
      $s181 = "\\jEg|A" fullword ascii /* score: '2.00'*/
      $s182 = "\\Mrqp-" fullword ascii /* score: '2.00'*/
      $s183 = "nCTRL+" fullword ascii /* score: '1.00'*/
      $s184 = "Fq<Rih" fullword ascii /* score: '1.00'*/
      $s185 = "! F' *) y0 :5u~" fullword ascii /* score: '1.00'*/
      $s186 = "1}HUF<" fullword ascii /* score: '1.00'*/
      $s187 = "rd)HTp" fullword ascii /* score: '1.00'*/
      $s188 = "G_B0b&" fullword ascii /* score: '1.00'*/
      $s189 = "je3%$8" fullword ascii /* score: '1.00'*/
      $s190 = "11)8\";! " fullword ascii /* score: '1.00'*/
      $s191 = "W_m+Z1" fullword ascii /* score: '1.00'*/
      $s192 = "sTvaPE" fullword ascii /* score: '1.00'*/
      $s193 = "I+^q0I" fullword ascii /* score: '1.00'*/
      $s194 = "R6ckCw" fullword ascii /* score: '1.00'*/
      $s195 = "t!KYSb" fullword ascii /* score: '1.00'*/
      $s196 = "6M:jQ]" fullword ascii /* score: '1.00'*/
      $s197 = "'+wFaf" fullword ascii /* score: '1.00'*/
      $s198 = "!?i2!\\" fullword ascii /* score: '1.00'*/
      $s199 = "oZ&>w#I" fullword ascii /* score: '1.00'*/
      $s200 = "l`:k|rF4$" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule sig_572d806c0b56d27fe05562301de6a9ed45cda3f36aef2f6e370867d9f3847013 {
   meta:
      description = "Amadey_MALW - file 572d806c0b56d27fe05562301de6a9ed45cda3f36aef2f6e370867d9f3847013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "572d806c0b56d27fe05562301de6a9ed45cda3f36aef2f6e370867d9f3847013"
   strings:
      $s1 = "ataL.NgB" fullword ascii /* score: '10.00'*/
      $s2 = "* \\\\Oa" fullword ascii /* score: '9.00'*/
      $s3 = "0N.tXTmP" fullword ascii /* score: '8.00'*/
      $s4 = "ezviljwn" fullword ascii /* score: '8.00'*/
      $s5 = "vbRTS- " fullword ascii /* score: '8.00'*/
      $s6 = "mlkfqtwe" fullword ascii /* score: '8.00'*/
      $s7 = "P6T6X6\\6<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s8 = "yal.aRP" fullword ascii /* score: '7.00'*/
      $s9 = "/a{@EYE\\j" fullword ascii /* score: '6.00'*/
      $s10 = "hqboid" fullword ascii /* score: '5.00'*/
      $s11 = "6tO /i[" fullword ascii /* score: '5.00'*/
      $s12 = "#>PX- &" fullword ascii /* score: '5.00'*/
      $s13 = " hW+ 4" fullword ascii /* score: '5.00'*/
      $s14 = "tIlDF05" fullword ascii /* score: '5.00'*/
      $s15 = "- a1 `5 " fullword ascii /* score: '5.00'*/
      $s16 = "a6- zv" fullword ascii /* score: '5.00'*/
      $s17 = "!}P /I" fullword ascii /* score: '5.00'*/
      $s18 = "U& Q+ " fullword ascii /* score: '5.00'*/
      $s19 = " -f[P5" fullword ascii /* score: '5.00'*/
      $s20 = "yG -yP" fullword ascii /* score: '5.00'*/
      $s21 = "GIJVuqAIq6" fullword ascii /* score: '5.00'*/
      $s22 = "&- 6x4" fullword ascii /* score: '5.00'*/
      $s23 = "o- wC7" fullword ascii /* score: '5.00'*/
      $s24 = "<DN4 /L:L" fullword ascii /* score: '5.00'*/
      $s25 = "rLvLjO5" fullword ascii /* score: '5.00'*/
      $s26 = "-~%rbW%6" fullword ascii /* score: '5.00'*/
      $s27 = "B@> -2" fullword ascii /* score: '5.00'*/
      $s28 = "SI%UN- k" fullword ascii /* score: '5.00'*/
      $s29 = "1t- nu" fullword ascii /* score: '5.00'*/
      $s30 = "B1- S)" fullword ascii /* score: '5.00'*/
      $s31 = ")% /i}" fullword ascii /* score: '5.00'*/
      $s32 = " -YbQ%" fullword ascii /* score: '5.00'*/
      $s33 = "# `,`~" fullword ascii /* score: '5.00'*/
      $s34 = " /bLU*DL" fullword ascii /* score: '5.00'*/
      $s35 = "jmiV\"!" fullword ascii /* score: '4.00'*/
      $s36 = "waazn)!kb," fullword ascii /* score: '4.00'*/
      $s37 = "obNk&L9" fullword ascii /* score: '4.00'*/
      $s38 = "osMIFc_" fullword ascii /* score: '4.00'*/
      $s39 = "_e.yAO" fullword ascii /* score: '4.00'*/
      $s40 = "GQCY\\X" fullword ascii /* score: '4.00'*/
      $s41 = "ITQt?%" fullword ascii /* score: '4.00'*/
      $s42 = "xZptqsa" fullword ascii /* score: '4.00'*/
      $s43 = "iJyfBOx" fullword ascii /* score: '4.00'*/
      $s44 = "t`t2xhxJ]pP>x>" fullword ascii /* score: '4.00'*/
      $s45 = " xoDh&I{4" fullword ascii /* score: '4.00'*/
      $s46 = "rjNQ?2U" fullword ascii /* score: '4.00'*/
      $s47 = "QPOB%0Kp" fullword ascii /* score: '4.00'*/
      $s48 = "1QJTz5\"" fullword ascii /* score: '4.00'*/
      $s49 = "BSJs\\8:N" fullword ascii /* score: '4.00'*/
      $s50 = "ocxa9eHu[p)" fullword ascii /* score: '4.00'*/
      $s51 = "yYxswa|" fullword ascii /* score: '4.00'*/
      $s52 = "1fDxXEth" fullword ascii /* score: '4.00'*/
      $s53 = "XxXLr%Fb`Y" fullword ascii /* score: '4.00'*/
      $s54 = "XDgxo(*" fullword ascii /* score: '4.00'*/
      $s55 = "UVkKu6R" fullword ascii /* score: '4.00'*/
      $s56 = "wTlf(R-" fullword ascii /* score: '4.00'*/
      $s57 = "yAkb+Vys^(" fullword ascii /* score: '4.00'*/
      $s58 = "Nccc~9k" fullword ascii /* score: '4.00'*/
      $s59 = "}p*HPWy|`h" fullword ascii /* score: '4.00'*/
      $s60 = "YrKQ$-_" fullword ascii /* score: '4.00'*/
      $s61 = "RSZc[(;" fullword ascii /* score: '4.00'*/
      $s62 = ":bJKw\\lY" fullword ascii /* score: '4.00'*/
      $s63 = ">#%d\\5" fullword ascii /* score: '4.00'*/
      $s64 = "@Tgba|(?" fullword ascii /* score: '4.00'*/
      $s65 = "j:pGdaE@m" fullword ascii /* score: '4.00'*/
      $s66 = "QmIL#`L" fullword ascii /* score: '4.00'*/
      $s67 = "dEIt|xc" fullword ascii /* score: '4.00'*/
      $s68 = "KfAR7EM" fullword ascii /* score: '4.00'*/
      $s69 = "FiIAxL%" fullword ascii /* score: '4.00'*/
      $s70 = "ZsITbkP" fullword ascii /* score: '4.00'*/
      $s71 = "taiX?J" fullword ascii /* score: '4.00'*/
      $s72 = "DlhN4)u" fullword ascii /* score: '4.00'*/
      $s73 = "GReY`H-" fullword ascii /* score: '4.00'*/
      $s74 = "MpHB\\O" fullword ascii /* score: '4.00'*/
      $s75 = "PRTNZ2\"U" fullword ascii /* score: '4.00'*/
      $s76 = "qXzW\\9" fullword ascii /* score: '4.00'*/
      $s77 = "|1QjLLT\"" fullword ascii /* score: '4.00'*/
      $s78 = "PnmUUB@R" fullword ascii /* score: '4.00'*/
      $s79 = "cvQT{Xp`" fullword ascii /* score: '4.00'*/
      $s80 = "/vK.Wmb" fullword ascii /* score: '4.00'*/
      $s81 = "XGzURo_iR" fullword ascii /* score: '4.00'*/
      $s82 = "wOBRW\\wR]q" fullword ascii /* score: '4.00'*/
      $s83 = "bNQZSB?#c" fullword ascii /* score: '4.00'*/
      $s84 = "QRSUVW^" fullword ascii /* score: '4.00'*/
      $s85 = "PBDzINx" fullword ascii /* score: '4.00'*/
      $s86 = "fHhO4>B" fullword ascii /* score: '4.00'*/
      $s87 = "lJEz8pK" fullword ascii /* score: '4.00'*/
      $s88 = "HnxTX.c" fullword ascii /* score: '4.00'*/
      $s89 = "[yATb3de" fullword ascii /* score: '4.00'*/
      $s90 = "V6.etS" fullword ascii /* score: '4.00'*/
      $s91 = "`gpWHG2-A" fullword ascii /* score: '4.00'*/
      $s92 = "%bCOs %F" fullword ascii /* score: '4.00'*/
      $s93 = "xPIt@$pp" fullword ascii /* score: '4.00'*/
      $s94 = " .sHP<" fullword ascii /* score: '4.00'*/
      $s95 = "WvuZ(Au" fullword ascii /* score: '4.00'*/
      $s96 = "SBQu=Ct" fullword ascii /* score: '4.00'*/
      $s97 = "PTJla8uY\"X" fullword ascii /* score: '4.00'*/
      $s98 = "eption I" fullword ascii /* score: '4.00'*/
      $s99 = "NYKP&^l" fullword ascii /* score: '4.00'*/
      $s100 = "|yzWV9iU" fullword ascii /* score: '4.00'*/
      $s101 = "TFRsOf~" fullword ascii /* score: '4.00'*/
      $s102 = "SCZxvZ(" fullword ascii /* score: '4.00'*/
      $s103 = "A*6cIFE6\\" fullword ascii /* score: '4.00'*/
      $s104 = "z7JUgX_:<" fullword ascii /* score: '4.00'*/
      $s105 = "LpPxt|~K" fullword ascii /* score: '4.00'*/
      $s106 = ",_`9.BKpLX~J" fullword ascii /* score: '4.00'*/
      $s107 = "[lUbi~uc" fullword ascii /* score: '4.00'*/
      $s108 = "RWzQ8`r" fullword ascii /* score: '4.00'*/
      $s109 = " TwrW^\"%E}" fullword ascii /* score: '4.00'*/
      $s110 = "CKVuYST" fullword ascii /* score: '4.00'*/
      $s111 = "DtKIWP\\" fullword ascii /* score: '4.00'*/
      $s112 = "*FvKBn-;" fullword ascii /* score: '4.00'*/
      $s113 = "VEFl~IDIb" fullword ascii /* score: '4.00'*/
      $s114 = "/PfgTdN`%X" fullword ascii /* score: '4.00'*/
      $s115 = "aGVN!M)" fullword ascii /* score: '4.00'*/
      $s116 = "a'&QHtXH$0" fullword ascii /* score: '4.00'*/
      $s117 = "vnSZ\\)" fullword ascii /* score: '4.00'*/
      $s118 = "NdIE'\\bYH" fullword ascii /* score: '4.00'*/
      $s119 = "TXDf1N+" fullword ascii /* score: '4.00'*/
      $s120 = "yEiQQ)0I$" fullword ascii /* score: '4.00'*/
      $s121 = "RKAQbD6 x" fullword ascii /* score: '4.00'*/
      $s122 = "[Pgskt_Z]t" fullword ascii /* score: '4.00'*/
      $s123 = "TpvPRD<2" fullword ascii /* score: '4.00'*/
      $s124 = "RdQq?$" fullword ascii /* score: '4.00'*/
      $s125 = "4wKMrH'G" fullword ascii /* score: '4.00'*/
      $s126 = "Hnawh,*#" fullword ascii /* score: '4.00'*/
      $s127 = "Pzlcv!" fullword ascii /* score: '4.00'*/
      $s128 = "ssly:uQ" fullword ascii /* score: '4.00'*/
      $s129 = "XgGpBf9#" fullword ascii /* score: '4.00'*/
      $s130 = "aDLB`K5" fullword ascii /* score: '4.00'*/
      $s131 = "-XeigL|S" fullword ascii /* score: '4.00'*/
      $s132 = ">PKLLM!d" fullword ascii /* score: '4.00'*/
      $s133 = "zH.vlC" fullword ascii /* score: '4.00'*/
      $s134 = "Utes~p^" fullword ascii /* score: '4.00'*/
      $s135 = "cCOyN,$x" fullword ascii /* score: '4.00'*/
      $s136 = "ZUEK%`D" fullword ascii /* score: '4.00'*/
      $s137 = "wfZUpZn" fullword ascii /* score: '4.00'*/
      $s138 = "2Ojde@-}" fullword ascii /* score: '4.00'*/
      $s139 = "UMLc<:O" fullword ascii /* score: '4.00'*/
      $s140 = "PAXKSR[l" fullword ascii /* score: '4.00'*/
      $s141 = "bpbJTfR_" fullword ascii /* score: '4.00'*/
      $s142 = "stiL+UHW(" fullword ascii /* score: '4.00'*/
      $s143 = "YUtYS~L" fullword ascii /* score: '4.00'*/
      $s144 = "LLdAD  l" fullword ascii /* score: '4.00'*/
      $s145 = "biN_4t" fullword ascii /* score: '4.00'*/
      $s146 = "q:ysvRx4x" fullword ascii /* score: '4.00'*/
      $s147 = "uXKtOTz" fullword ascii /* score: '4.00'*/
      $s148 = "fHHS(UE" fullword ascii /* score: '4.00'*/
      $s149 = "nWMJ%pS" fullword ascii /* score: '4.00'*/
      $s150 = "mbwx\\/Y" fullword ascii /* score: '4.00'*/
      $s151 = "*uEXgUehO" fullword ascii /* score: '4.00'*/
      $s152 = "QRIB9vhP19" fullword ascii /* score: '4.00'*/
      $s153 = "kPST2(4" fullword ascii /* score: '4.00'*/
      $s154 = "kTwip?" fullword ascii /* score: '4.00'*/
      $s155 = "hxuOC\"" fullword ascii /* score: '4.00'*/
      $s156 = "9H]<'[~bRWr0~Q" fullword ascii /* score: '4.00'*/
      $s157 = "PyDv28A" fullword ascii /* score: '4.00'*/
      $s158 = "W\\1r\\8%n-J" fullword ascii /* score: '3.50'*/
      $s159 = "%g;(\"}(" fullword ascii /* score: '3.50'*/
      $s160 = "0~3[%z:" fullword ascii /* score: '3.50'*/
      $s161 = "|!E`b:\"" fullword ascii /* score: '3.00'*/
      $s162 = " fwiud" fullword ascii /* score: '3.00'*/
      $s163 = "\\S$3@/" fullword ascii /* score: '2.00'*/
      $s164 = "\\P[YnS" fullword ascii /* score: '2.00'*/
      $s165 = "QMhVk8" fullword ascii /* score: '2.00'*/
      $s166 = "\\&1!S@O" fullword ascii /* score: '2.00'*/
      $s167 = "vyWN04" fullword ascii /* score: '2.00'*/
      $s168 = "\\#lp}p" fullword ascii /* score: '2.00'*/
      $s169 = "\\<O$+D" fullword ascii /* score: '2.00'*/
      $s170 = "JdDA34" fullword ascii /* score: '2.00'*/
      $s171 = "\\rc*D0" fullword ascii /* score: '2.00'*/
      $s172 = "bgvxH5" fullword ascii /* score: '2.00'*/
      $s173 = "BiWqi2" fullword ascii /* score: '2.00'*/
      $s174 = "\\|C'@o" fullword ascii /* score: '2.00'*/
      $s175 = "\\\\^R]Y" fullword ascii /* score: '2.00'*/
      $s176 = "\\:|k5=" fullword ascii /* score: '2.00'*/
      $s177 = "CidB51" fullword ascii /* score: '2.00'*/
      $s178 = "\\%_@)U" fullword ascii /* score: '2.00'*/
      $s179 = "\\f8|@^" fullword ascii /* score: '2.00'*/
      $s180 = "\\RWqy%" fullword ascii /* score: '2.00'*/
      $s181 = "\\oRA-1" fullword ascii /* score: '2.00'*/
      $s182 = "QhoI72" fullword ascii /* score: '2.00'*/
      $s183 = "\\m9X0," fullword ascii /* score: '2.00'*/
      $s184 = "\\&RVO@" fullword ascii /* score: '2.00'*/
      $s185 = "\\;XQ,TY%" fullword ascii /* score: '2.00'*/
      $s186 = "\\qnk N" fullword ascii /* score: '2.00'*/
      $s187 = "\\cB}%O" fullword ascii /* score: '2.00'*/
      $s188 = "JOZtT5" fullword ascii /* score: '2.00'*/
      $s189 = "\\WYt[Q[" fullword ascii /* score: '2.00'*/
      $s190 = "rVTZe4" fullword ascii /* score: '2.00'*/
      $s191 = "\\@/l]b" fullword ascii /* score: '2.00'*/
      $s192 = "\\ s(;Ef" fullword ascii /* score: '2.00'*/
      $s193 = "\\ H[TQ" fullword ascii /* score: '2.00'*/
      $s194 = "PDlTF0" fullword ascii /* score: '2.00'*/
      $s195 = "\\(ZBGL" fullword ascii /* score: '2.00'*/
      $s196 = "QXHh58" fullword ascii /* score: '2.00'*/
      $s197 = "\\^g<]:" fullword ascii /* score: '2.00'*/
      $s198 = "\\VV21F" fullword ascii /* score: '2.00'*/
      $s199 = "SoZJ41" fullword ascii /* score: '2.00'*/
      $s200 = "\\iT0w0" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule sig_1dbbf81d6f4b2222b37594e8ff30672bf85fd360f347cbd20b1a5d7b841dd276 {
   meta:
      description = "Amadey_MALW - file 1dbbf81d6f4b2222b37594e8ff30672bf85fd360f347cbd20b1a5d7b841dd276"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "1dbbf81d6f4b2222b37594e8ff30672bf85fd360f347cbd20b1a5d7b841dd276"
   strings:
      $s1 = "* =HzC" fullword ascii /* score: '9.00'*/
      $s2 = "ZOWe- n" fullword ascii /* score: '8.00'*/
      $s3 = "plzfkdac" fullword ascii /* score: '8.00'*/
      $s4 = "pcxsfzhs" fullword ascii /* score: '8.00'*/
      $s5 = "6<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s6 = "i%r%oJ" fullword ascii /* score: '5.00'*/
      $s7 = "$[%yV%" fullword ascii /* score: '5.00'*/
      $s8 = "2- ymH" fullword ascii /* score: '5.00'*/
      $s9 = ">1zaW* {v 3" fullword ascii /* score: '5.00'*/
      $s10 = "\\9ZWQI/Xn" fullword ascii /* score: '5.00'*/
      $s11 = "(x&v- tA" fullword ascii /* score: '5.00'*/
      $s12 = ",%Ad- " fullword ascii /* score: '5.00'*/
      $s13 = "bpSanO5" fullword ascii /* score: '5.00'*/
      $s14 = "@r<u* ,?" fullword ascii /* score: '5.00'*/
      $s15 = "%k%qdG" fullword ascii /* score: '5.00'*/
      $s16 = " -CR'p" fullword ascii /* score: '5.00'*/
      $s17 = "-`+ l!" fullword ascii /* score: '5.00'*/
      $s18 = "T`#yP(- " fullword ascii /* score: '5.00'*/
      $s19 = " -%tVZ" fullword ascii /* score: '5.00'*/
      $s20 = "2;P- 5" fullword ascii /* score: '5.00'*/
      $s21 = "9<g- 8" fullword ascii /* score: '5.00'*/
      $s22 = "hhmsbl" fullword ascii /* score: '5.00'*/
      $s23 = "- SH??8" fullword ascii /* score: '5.00'*/
      $s24 = "%ed%~k" fullword ascii /* score: '5.00'*/
      $s25 = ")%r%VE" fullword ascii /* score: '5.00'*/
      $s26 = "- n(G!%" fullword ascii /* score: '5.00'*/
      $s27 = "1b- ;q" fullword ascii /* score: '5.00'*/
      $s28 = "ception sIvf" fullword ascii /* score: '4.00'*/
      $s29 = "wuzQb[A" fullword ascii /* score: '4.00'*/
      $s30 = "2AfAU!k" fullword ascii /* score: '4.00'*/
      $s31 = "XnQJ]Dv" fullword ascii /* score: '4.00'*/
      $s32 = "tpZtcE!" fullword ascii /* score: '4.00'*/
      $s33 = "ydPlPwK" fullword ascii /* score: '4.00'*/
      $s34 = "'::%i!" fullword ascii /* score: '4.00'*/
      $s35 = "CpWNx,=:T<" fullword ascii /* score: '4.00'*/
      $s36 = "ptHo!%I" fullword ascii /* score: '4.00'*/
      $s37 = "bmMeU0p" fullword ascii /* score: '4.00'*/
      $s38 = "SPsp0R=" fullword ascii /* score: '4.00'*/
      $s39 = "&cKqG6\"6" fullword ascii /* score: '4.00'*/
      $s40 = "qsLf%_ 6>@" fullword ascii /* score: '4.00'*/
      $s41 = "IXPEHx|" fullword ascii /* score: '4.00'*/
      $s42 = "]vJRunE" fullword ascii /* score: '4.00'*/
      $s43 = "DC.Ril" fullword ascii /* score: '4.00'*/
      $s44 = "Eh.%d3" fullword ascii /* score: '4.00'*/
      $s45 = "e_(`=.ktw" fullword ascii /* score: '4.00'*/
      $s46 = "bNjIkV*" fullword ascii /* score: '4.00'*/
      $s47 = "sWQpP\"" fullword ascii /* score: '4.00'*/
      $s48 = "eFeFb.w" fullword ascii /* score: '4.00'*/
      $s49 = " eOxV!" fullword ascii /* score: '4.00'*/
      $s50 = "N.gwF." fullword ascii /* score: '4.00'*/
      $s51 = "HYlsEVL" fullword ascii /* score: '4.00'*/
      $s52 = ")AAWT_bY" fullword ascii /* score: '4.00'*/
      $s53 = "uPMcO)3" fullword ascii /* score: '4.00'*/
      $s54 = "IuXYKAV" fullword ascii /* score: '4.00'*/
      $s55 = "nD.GVx" fullword ascii /* score: '4.00'*/
      $s56 = "bKDT:3:'" fullword ascii /* score: '4.00'*/
      $s57 = "J.iUu<" fullword ascii /* score: '4.00'*/
      $s58 = "wJLd-HUt{" fullword ascii /* score: '4.00'*/
      $s59 = "xiYDl>d>+$" fullword ascii /* score: '4.00'*/
      $s60 = "YliWysI" fullword ascii /* score: '4.00'*/
      $s61 = "/dAatN+`" fullword ascii /* score: '4.00'*/
      $s62 = "zHWv((a" fullword ascii /* score: '4.00'*/
      $s63 = "i-Phhl?" fullword ascii /* score: '4.00'*/
      $s64 = "XXWRz!" fullword ascii /* score: '4.00'*/
      $s65 = "pPUv%/t" fullword ascii /* score: '4.00'*/
      $s66 = "WQiKt0e" fullword ascii /* score: '4.00'*/
      $s67 = "OxbZG)s<^" fullword ascii /* score: '4.00'*/
      $s68 = "zKgRz2i" fullword ascii /* score: '4.00'*/
      $s69 = "BBQJX!" fullword ascii /* score: '4.00'*/
      $s70 = "KauVPRT" fullword ascii /* score: '4.00'*/
      $s71 = "ws.LMhj+\"" fullword ascii /* score: '4.00'*/
      $s72 = "`hBbvNDE" fullword ascii /* score: '4.00'*/
      $s73 = "xlIoPRt" fullword ascii /* score: '4.00'*/
      $s74 = "vhtV$Bg" fullword ascii /* score: '4.00'*/
      $s75 = "_.eVg@" fullword ascii /* score: '4.00'*/
      $s76 = "/SyqJ@#L" fullword ascii /* score: '4.00'*/
      $s77 = "SVtFB!" fullword ascii /* score: '4.00'*/
      $s78 = "bgEQuMb>" fullword ascii /* score: '4.00'*/
      $s79 = "<ZiCnDi3ulS" fullword ascii /* score: '4.00'*/
      $s80 = "bFfA-+:" fullword ascii /* score: '4.00'*/
      $s81 = "poLh6EQ" fullword ascii /* score: '4.00'*/
      $s82 = "iSLq-Ok" fullword ascii /* score: '4.00'*/
      $s83 = "BfEI,<\\" fullword ascii /* score: '4.00'*/
      $s84 = "Z]tjZU~$%" fullword ascii /* score: '4.00'*/
      $s85 = "YXhT._(" fullword ascii /* score: '4.00'*/
      $s86 = "5\\tItU?T" fullword ascii /* score: '4.00'*/
      $s87 = "vGtZU,-SF" fullword ascii /* score: '4.00'*/
      $s88 = "kbwMh%\\" fullword ascii /* score: '4.00'*/
      $s89 = "dHJKwCg" fullword ascii /* score: '4.00'*/
      $s90 = "GL.TZa" fullword ascii /* score: '4.00'*/
      $s91 = "xiFymdz" fullword ascii /* score: '4.00'*/
      $s92 = "n1ZeWTQ/p" fullword ascii /* score: '4.00'*/
      $s93 = "bkRTY%E" fullword ascii /* score: '4.00'*/
      $s94 = "-cGpc?" fullword ascii /* score: '4.00'*/
      $s95 = "_ltoZsB/" fullword ascii /* score: '4.00'*/
      $s96 = ". .lqT" fullword ascii /* score: '4.00'*/
      $s97 = "ALTo5p2" fullword ascii /* score: '4.00'*/
      $s98 = "|JrtJK+~w" fullword ascii /* score: '4.00'*/
      $s99 = "BvYS/x8N" fullword ascii /* score: '4.00'*/
      $s100 = "xdXOQqf~No!Kp" fullword ascii /* score: '4.00'*/
      $s101 = "xPQTJY*" fullword ascii /* score: '4.00'*/
      $s102 = "y[Ibcvlg!i^" fullword ascii /* score: '4.00'*/
      $s103 = "IGJf\\t" fullword ascii /* score: '4.00'*/
      $s104 = "SiDQl4u" fullword ascii /* score: '4.00'*/
      $s105 = "D%MYkE! 6f1" fullword ascii /* score: '4.00'*/
      $s106 = "hvmJ~~`" fullword ascii /* score: '4.00'*/
      $s107 = "QjRw\\lp" fullword ascii /* score: '4.00'*/
      $s108 = "2XWBPAs_o" fullword ascii /* score: '4.00'*/
      $s109 = ".Gnwh42w" fullword ascii /* score: '4.00'*/
      $s110 = "VdSpI$(" fullword ascii /* score: '4.00'*/
      $s111 = "iNsaYLN" fullword ascii /* score: '4.00'*/
      $s112 = "FwQlM<o" fullword ascii /* score: '4.00'*/
      $s113 = "SjnnZm\"" fullword ascii /* score: '4.00'*/
      $s114 = "BfNQe4Ic" fullword ascii /* score: '4.00'*/
      $s115 = "KubGY]E" fullword ascii /* score: '4.00'*/
      $s116 = "QaeCZm]+Q03" fullword ascii /* score: '4.00'*/
      $s117 = "kpDDdKJ" fullword ascii /* score: '4.00'*/
      $s118 = "KQsJ?k" fullword ascii /* score: '4.00'*/
      $s119 = "PhDxwWU" fullword ascii /* score: '4.00'*/
      $s120 = "(yvEJBCc" fullword ascii /* score: '4.00'*/
      $s121 = "vueiI_N" fullword ascii /* score: '4.00'*/
      $s122 = "YJSqt0K" fullword ascii /* score: '4.00'*/
      $s123 = "Qqvl)>Z" fullword ascii /* score: '4.00'*/
      $s124 = "gDiUyXK" fullword ascii /* score: '4.00'*/
      $s125 = "8mYsL$)d" fullword ascii /* score: '4.00'*/
      $s126 = "SdTpER0LL" fullword ascii /* score: '4.00'*/
      $s127 = "XYxmhI)" fullword ascii /* score: '4.00'*/
      $s128 = "hhXPABO/'" fullword ascii /* score: '4.00'*/
      $s129 = "%YNbZ!" fullword ascii /* score: '4.00'*/
      $s130 = "KifZ%% " fullword ascii /* score: '4.00'*/
      $s131 = "KXTyOJa" fullword ascii /* score: '4.00'*/
      $s132 = "\"ceKREaND" fullword ascii /* score: '4.00'*/
      $s133 = "esmHHhd:" fullword ascii /* score: '4.00'*/
      $s134 = "WafMxTH" fullword ascii /* score: '4.00'*/
      $s135 = "B\"]~XKLXVSh\"0\"z" fullword ascii /* score: '4.00'*/
      $s136 = "MYpB\">j" fullword ascii /* score: '4.00'*/
      $s137 = "*FTKzyHU" fullword ascii /* score: '4.00'*/
      $s138 = "uGgYD\"" fullword ascii /* score: '4.00'*/
      $s139 = "ajLqm!" fullword ascii /* score: '4.00'*/
      $s140 = "RTMB92U" fullword ascii /* score: '4.00'*/
      $s141 = "2ZWTWe?" fullword ascii /* score: '4.00'*/
      $s142 = "FDHO\\-" fullword ascii /* score: '4.00'*/
      $s143 = "QHMP?_d" fullword ascii /* score: '4.00'*/
      $s144 = "usfy?r6cq>!J[" fullword ascii /* score: '4.00'*/
      $s145 = "SQYNK!M?" fullword ascii /* score: '4.00'*/
      $s146 = "zmkE\"[@" fullword ascii /* score: '4.00'*/
      $s147 = "2RgDM3X=N" fullword ascii /* score: '4.00'*/
      $s148 = "_ )H%m;)o|" fullword ascii /* score: '3.50'*/
      $s149 = "y}C%e," fullword ascii /* score: '3.50'*/
      $s150 = "R)%w,D" fullword ascii /* score: '3.50'*/
      $s151 = "%q;Iw[" fullword ascii /* score: '3.50'*/
      $s152 = "LPL=%b," fullword ascii /* score: '3.50'*/
      $s153 = "iv%j:!" fullword ascii /* score: '3.50'*/
      $s154 = "X:\"u-" fullword ascii /* score: '3.00'*/
      $s155 = "gRtlA.coca" fullword ascii /* score: '3.00'*/
      $s156 = "haAhC7" fullword ascii /* score: '2.00'*/
      $s157 = "\\9I4dZm+(H" fullword ascii /* score: '2.00'*/
      $s158 = "\\AJRZG" fullword ascii /* score: '2.00'*/
      $s159 = "\\OV)+?" fullword ascii /* score: '2.00'*/
      $s160 = "\\b8[,X" fullword ascii /* score: '2.00'*/
      $s161 = "TQHDA0" fullword ascii /* score: '2.00'*/
      $s162 = "\\#hR4-" fullword ascii /* score: '2.00'*/
      $s163 = "\\pS^&r" fullword ascii /* score: '2.00'*/
      $s164 = "\\&jc/]" fullword ascii /* score: '2.00'*/
      $s165 = "\\@\\(.>4EYh`" fullword ascii /* score: '2.00'*/
      $s166 = "mkldS0" fullword ascii /* score: '2.00'*/
      $s167 = "\\@\\NsE" fullword ascii /* score: '2.00'*/
      $s168 = "\\aZ)?U" fullword ascii /* score: '2.00'*/
      $s169 = "\\C3g'(V" fullword ascii /* score: '2.00'*/
      $s170 = "\\O/E9'" fullword ascii /* score: '2.00'*/
      $s171 = "\\w|HR}I" fullword ascii /* score: '2.00'*/
      $s172 = "\\tsZw{L" fullword ascii /* score: '2.00'*/
      $s173 = "\\/\"B^!XVU" fullword ascii /* score: '2.00'*/
      $s174 = "hMpYO1" fullword ascii /* score: '2.00'*/
      $s175 = "\\`&*$+" fullword ascii /* score: '2.00'*/
      $s176 = "\\zR^YB)" fullword ascii /* score: '2.00'*/
      $s177 = "\\{kK?%X" fullword ascii /* score: '2.00'*/
      $s178 = "UALR67" fullword ascii /* score: '2.00'*/
      $s179 = "\\okd4/)" fullword ascii /* score: '2.00'*/
      $s180 = "\\c\\J1 )" fullword ascii /* score: '2.00'*/
      $s181 = "\\=3>rb" fullword ascii /* score: '2.00'*/
      $s182 = "XuyBN9" fullword ascii /* score: '2.00'*/
      $s183 = "\\1z}V+" fullword ascii /* score: '2.00'*/
      $s184 = "\\W\\~-W" fullword ascii /* score: '2.00'*/
      $s185 = "\\'T@H#" fullword ascii /* score: '2.00'*/
      $s186 = "\\_r M X$" fullword ascii /* score: '2.00'*/
      $s187 = "\\S<7,-" fullword ascii /* score: '2.00'*/
      $s188 = "\\pGdxSU" fullword ascii /* score: '2.00'*/
      $s189 = "\\RwBCe" fullword ascii /* score: '2.00'*/
      $s190 = "\\,OUDb" fullword ascii /* score: '2.00'*/
      $s191 = "\\i8EZ4" fullword ascii /* score: '2.00'*/
      $s192 = "UYOiy5" fullword ascii /* score: '2.00'*/
      $s193 = "\\a$9%)" fullword ascii /* score: '2.00'*/
      $s194 = "\\V^Y1q" fullword ascii /* score: '2.00'*/
      $s195 = "\\2t`X|" fullword ascii /* score: '2.00'*/
      $s196 = "\\J&\"Tq" fullword ascii /* score: '2.00'*/
      $s197 = "\\)$&\"," fullword ascii /* score: '2.00'*/
      $s198 = "\\_q^k]" fullword ascii /* score: '2.00'*/
      $s199 = "\\|d/4+<" fullword ascii /* score: '2.00'*/
      $s200 = "\\_yKiw" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb {
   meta:
      description = "Amadey_MALW - file e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb"
   strings:
      $s1 = "zancqolw" fullword ascii /* score: '8.00'*/
      $s2 = "_%JuyM%Uom" fullword ascii /* score: '8.00'*/
      $s3 = "ulhvadyy" fullword ascii /* score: '8.00'*/
      $s4 = "?<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s5 = "\\r%wgV%" fullword ascii /* score: '6.00'*/
      $s6 = "f EYeZ" fullword ascii /* score: '6.00'*/
      $s7 = "BBf*- !" fullword ascii /* score: '5.00'*/
      $s8 = "z^W* [" fullword ascii /* score: '5.00'*/
      $s9 = "7- t^G" fullword ascii /* score: '5.00'*/
      $s10 = "%WY%iS" fullword ascii /* score: '5.00'*/
      $s11 = "<fl@t'}+ " fullword ascii /* score: '5.00'*/
      $s12 = "HWMao20" fullword ascii /* score: '5.00'*/
      $s13 = "%Va%Lp<" fullword ascii /* score: '5.00'*/
      $s14 = "z%p+-G+ k" fullword ascii /* score: '5.00'*/
      $s15 = ")z/ -1" fullword ascii /* score: '5.00'*/
      $s16 = "%e%/[@" fullword ascii /* score: '5.00'*/
      $s17 = "- 3)J8" fullword ascii /* score: '5.00'*/
      $s18 = "f%flC%" fullword ascii /* score: '5.00'*/
      $s19 = "f&Z+ )" fullword ascii /* score: '5.00'*/
      $s20 = "ibgmsr" fullword ascii /* score: '5.00'*/
      $s21 = "aDXwVY9" fullword ascii /* score: '5.00'*/
      $s22 = "^Z@{P* " fullword ascii /* score: '5.00'*/
      $s23 = "KxUpCT2" fullword ascii /* score: '5.00'*/
      $s24 = "Jm-I* " fullword ascii /* score: '5.00'*/
      $s25 = ";/`t -E" fullword ascii /* score: '5.00'*/
      $s26 = "M%eV%U" fullword ascii /* score: '5.00'*/
      $s27 = "7Ug* !" fullword ascii /* score: '5.00'*/
      $s28 = "OUTpPro" fullword ascii /* score: '4.00'*/
      $s29 = "skpX)mO" fullword ascii /* score: '4.00'*/
      $s30 = "|Vt~|.DnR" fullword ascii /* score: '4.00'*/
      $s31 = "XcDX(S " fullword ascii /* score: '4.00'*/
      $s32 = "aqpNcW:" fullword ascii /* score: '4.00'*/
      $s33 = "QRPspxO" fullword ascii /* score: '4.00'*/
      $s34 = "VGRub[_" fullword ascii /* score: '4.00'*/
      $s35 = "*mAFm!" fullword ascii /* score: '4.00'*/
      $s36 = "]fFRpMb[)" fullword ascii /* score: '4.00'*/
      $s37 = "THIn? |" fullword ascii /* score: '4.00'*/
      $s38 = "RusG$ %Y" fullword ascii /* score: '4.00'*/
      $s39 = "dgjZaei" fullword ascii /* score: '4.00'*/
      $s40 = "QaiW0:1" fullword ascii /* score: '4.00'*/
      $s41 = "6pNyAZ_l`" fullword ascii /* score: '4.00'*/
      $s42 = "ifduQYY" fullword ascii /* score: '4.00'*/
      $s43 = "DPEi\"?*" fullword ascii /* score: '4.00'*/
      $s44 = ")32cnpeJl$" fullword ascii /* score: '4.00'*/
      $s45 = "VKNYDPj" fullword ascii /* score: '4.00'*/
      $s46 = " .Hmh$Z" fullword ascii /* score: '4.00'*/
      $s47 = "QnId-,)" fullword ascii /* score: '4.00'*/
      $s48 = "VTfc2n%y[" fullword ascii /* score: '4.00'*/
      $s49 = "01:AHNJ0].~L`X<" fullword ascii /* score: '4.00'*/
      $s50 = "CPPhRX&" fullword ascii /* score: '4.00'*/
      $s51 = "oLZt}/G" fullword ascii /* score: '4.00'*/
      $s52 = "pwRo&&1X" fullword ascii /* score: '4.00'*/
      $s53 = ":zFzp&.?C" fullword ascii /* score: '4.00'*/
      $s54 = "IxoQ%s3" fullword ascii /* score: '4.00'*/
      $s55 = "EsVn.:R" fullword ascii /* score: '4.00'*/
      $s56 = "aBGDh\\@I" fullword ascii /* score: '4.00'*/
      $s57 = "?lYcoL:U" fullword ascii /* score: '4.00'*/
      $s58 = "skje\\U" fullword ascii /* score: '4.00'*/
      $s59 = "edbp)%|" fullword ascii /* score: '4.00'*/
      $s60 = "ByqQ\"@" fullword ascii /* score: '4.00'*/
      $s61 = "0bXqI 1f" fullword ascii /* score: '4.00'*/
      $s62 = "PWud@\\" fullword ascii /* score: '4.00'*/
      $s63 = "aUQR\"\\" fullword ascii /* score: '4.00'*/
      $s64 = "siRFN-%" fullword ascii /* score: '4.00'*/
      $s65 = "<g.XEZ" fullword ascii /* score: '4.00'*/
      $s66 = "geJc[[Q0" fullword ascii /* score: '4.00'*/
      $s67 = "bNoiFk*" fullword ascii /* score: '4.00'*/
      $s68 = "UUHbhJt" fullword ascii /* score: '4.00'*/
      $s69 = "oTLL96C!" fullword ascii /* score: '4.00'*/
      $s70 = "oQiXa:|" fullword ascii /* score: '4.00'*/
      $s71 = "$;ZUtH,!$A'@" fullword ascii /* score: '4.00'*/
      $s72 = "iuDf[-5" fullword ascii /* score: '4.00'*/
      $s73 = "ygIWF\"." fullword ascii /* score: '4.00'*/
      $s74 = "LlUXd\"A" fullword ascii /* score: '4.00'*/
      $s75 = "wPoFKVL" fullword ascii /* score: '4.00'*/
      $s76 = "CRAhmXx" fullword ascii /* score: '4.00'*/
      $s77 = "PfiSet&" fullword ascii /* score: '4.00'*/
      $s78 = "tpscd0g" fullword ascii /* score: '4.00'*/
      $s79 = "aikuS?" fullword ascii /* score: '4.00'*/
      $s80 = "uTAH#Ov" fullword ascii /* score: '4.00'*/
      $s81 = "MSqxtCx" fullword ascii /* score: '4.00'*/
      $s82 = "FAonkP)" fullword ascii /* score: '4.00'*/
      $s83 = "PAQK0\\T" fullword ascii /* score: '4.00'*/
      $s84 = "cUxh=~>!" fullword ascii /* score: '4.00'*/
      $s85 = "raWBN]H" fullword ascii /* score: '4.00'*/
      $s86 = "BUvbR(x" fullword ascii /* score: '4.00'*/
      $s87 = "vZUjZs/" fullword ascii /* score: '4.00'*/
      $s88 = "VKRu^yZy " fullword ascii /* score: '4.00'*/
      $s89 = "QECxawI" fullword ascii /* score: '4.00'*/
      $s90 = "uiVQZk9|" fullword ascii /* score: '4.00'*/
      $s91 = "Y\"xbe,%d8" fullword ascii /* score: '4.00'*/
      $s92 = "cDGr!T+" fullword ascii /* score: '4.00'*/
      $s93 = "&LAXP_W]T" fullword ascii /* score: '4.00'*/
      $s94 = "WFZJhoHc" fullword ascii /* score: '4.00'*/
      $s95 = "XzUxb!" fullword ascii /* score: '4.00'*/
      $s96 = ".NXo@K@\\R" fullword ascii /* score: '4.00'*/
      $s97 = "KRTQC!" fullword ascii /* score: '4.00'*/
      $s98 = "tptgj,|" fullword ascii /* score: '4.00'*/
      $s99 = "ITBjO%W" fullword ascii /* score: '4.00'*/
      $s100 = "WT_PJUA!7" fullword ascii /* score: '4.00'*/
      $s101 = "2HmTJXi.U" fullword ascii /* score: '4.00'*/
      $s102 = "O}GDskF>7" fullword ascii /* score: '4.00'*/
      $s103 = "PDjWsK\\" fullword ascii /* score: '4.00'*/
      $s104 = "lj.Shg" fullword ascii /* score: '4.00'*/
      $s105 = "kViq-}c" fullword ascii /* score: '4.00'*/
      $s106 = "iNXQX,HT" fullword ascii /* score: '4.00'*/
      $s107 = "APFcd|J" fullword ascii /* score: '4.00'*/
      $s108 = "jWAx6Ac" fullword ascii /* score: '4.00'*/
      $s109 = "qwyvGt<o<" fullword ascii /* score: '4.00'*/
      $s110 = ".wLm!)" fullword ascii /* score: '4.00'*/
      $s111 = "NrpJ0XI" fullword ascii /* score: '4.00'*/
      $s112 = "tuYsh*d" fullword ascii /* score: '4.00'*/
      $s113 = "WYAk_/X" fullword ascii /* score: '4.00'*/
      $s114 = "[kwSM6#ii" fullword ascii /* score: '4.00'*/
      $s115 = ".jiHdS\"" fullword ascii /* score: '4.00'*/
      $s116 = "8U\\xRwV#R&" fullword ascii /* score: '4.00'*/
      $s117 = "PQRSU%VW" fullword ascii /* score: '4.00'*/
      $s118 = "&lTPj| hOt\\" fullword ascii /* score: '4.00'*/
      $s119 = "dUhH_WZ" fullword ascii /* score: '4.00'*/
      $s120 = "CDwL-Dk" fullword ascii /* score: '4.00'*/
      $s121 = ";`.OYz" fullword ascii /* score: '4.00'*/
      $s122 = "d.FVh@" fullword ascii /* score: '4.00'*/
      $s123 = "IHQl?<Ag" fullword ascii /* score: '4.00'*/
      $s124 = "qXplvQk" fullword ascii /* score: '4.00'*/
      $s125 = "_tmRBn+&vE" fullword ascii /* score: '4.00'*/
      $s126 = "wFcTv7$" fullword ascii /* score: '4.00'*/
      $s127 = "oNPXI)z" fullword ascii /* score: '4.00'*/
      $s128 = "LzYbRh<" fullword ascii /* score: '4.00'*/
      $s129 = "?aKZUT>#" fullword ascii /* score: '4.00'*/
      $s130 = "CRYZJJ" fullword ascii /* score: '3.50'*/
      $s131 = "Exceptio" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s132 = "\\I^t&KRS" fullword ascii /* score: '2.00'*/
      $s133 = "\\v/vuQ" fullword ascii /* score: '2.00'*/
      $s134 = "\\IX2&W5" fullword ascii /* score: '2.00'*/
      $s135 = "RTKZ44" fullword ascii /* score: '2.00'*/
      $s136 = "\\9+@pO" fullword ascii /* score: '2.00'*/
      $s137 = "WYnI35" fullword ascii /* score: '2.00'*/
      $s138 = "FGnDL3" fullword ascii /* score: '2.00'*/
      $s139 = "PGeNH7" fullword ascii /* score: '2.00'*/
      $s140 = "\\O,q?zE" fullword ascii /* score: '2.00'*/
      $s141 = "\\URut>" fullword ascii /* score: '2.00'*/
      $s142 = "\\v,k[\"" fullword ascii /* score: '2.00'*/
      $s143 = "\\5vM.6" fullword ascii /* score: '2.00'*/
      $s144 = "\\xNX%{" fullword ascii /* score: '2.00'*/
      $s145 = "\\L&j@]d" fullword ascii /* score: '2.00'*/
      $s146 = "\\F:-i6:" fullword ascii /* score: '2.00'*/
      $s147 = "iTxe08" fullword ascii /* score: '2.00'*/
      $s148 = "\\eRbt~" fullword ascii /* score: '2.00'*/
      $s149 = "hawGI9" fullword ascii /* score: '2.00'*/
      $s150 = "\\1d 0`W0k" fullword ascii /* score: '2.00'*/
      $s151 = "\\_Rh`\"x" fullword ascii /* score: '2.00'*/
      $s152 = "nfBb92" fullword ascii /* score: '2.00'*/
      $s153 = "TkQPP7" fullword ascii /* score: '2.00'*/
      $s154 = "\\-Q2k9H" fullword ascii /* score: '2.00'*/
      $s155 = "\\O?*5C[" fullword ascii /* score: '2.00'*/
      $s156 = "\\H0f;h" fullword ascii /* score: '2.00'*/
      $s157 = "HbLdi0" fullword ascii /* score: '2.00'*/
      $s158 = "\\.|%PR" fullword ascii /* score: '2.00'*/
      $s159 = "\\FV,c/ " fullword ascii /* score: '2.00'*/
      $s160 = "\\ &PP`" fullword ascii /* score: '2.00'*/
      $s161 = "\\!zLCi" fullword ascii /* score: '2.00'*/
      $s162 = "\\cR]KZ" fullword ascii /* score: '2.00'*/
      $s163 = "\\,Qb)," fullword ascii /* score: '2.00'*/
      $s164 = "\\i@hm8" fullword ascii /* score: '2.00'*/
      $s165 = "\\B>,Q}" fullword ascii /* score: '2.00'*/
      $s166 = "\\Jl;P\"" fullword ascii /* score: '2.00'*/
      $s167 = "nCTRL+" fullword ascii /* score: '1.00'*/
      $s168 = ")3Kc/3" fullword ascii /* score: '1.00'*/
      $s169 = "_^][ZYX" fullword ascii /* score: '1.00'*/
      $s170 = "{s4wi4Y" fullword ascii /* score: '1.00'*/
      $s171 = "_^][ZY" fullword ascii /* score: '1.00'*/
      $s172 = "u\\LKy=" fullword ascii /* score: '1.00'*/
      $s173 = "Rx!cJm" fullword ascii /* score: '1.00'*/
      $s174 = "Ph\"{B+" fullword ascii /* score: '1.00'*/
      $s175 = "6%3wQs" fullword ascii /* score: '1.00'*/
      $s176 = "$T//Xh" fullword ascii /* score: '1.00'*/
      $s177 = ";^MfTXV" fullword ascii /* score: '1.00'*/
      $s178 = "2;_yBB" fullword ascii /* score: '1.00'*/
      $s179 = "^[ndlD" fullword ascii /* score: '1.00'*/
      $s180 = "&c)Ob1" fullword ascii /* score: '1.00'*/
      $s181 = "#-]) D" fullword ascii /* score: '1.00'*/
      $s182 = "-u-;t~" fullword ascii /* score: '1.00'*/
      $s183 = " 0` `?" fullword ascii /* score: '1.00'*/
      $s184 = ":@ZxB`" fullword ascii /* score: '1.00'*/
      $s185 = "5]YfE1" fullword ascii /* score: '1.00'*/
      $s186 = "b57hh<" fullword ascii /* score: '1.00'*/
      $s187 = ":QWv#V" fullword ascii /* score: '1.00'*/
      $s188 = "aWqL%P" fullword ascii /* score: '1.00'*/
      $s189 = "YUT]'P" fullword ascii /* score: '1.00'*/
      $s190 = ")M?iz:" fullword ascii /* score: '1.00'*/
      $s191 = "o`G!a]" fullword ascii /* score: '1.00'*/
      $s192 = ":>\\$-S" fullword ascii /* score: '1.00'*/
      $s193 = "Oga2-G" fullword ascii /* score: '1.00'*/
      $s194 = "  xCSN" fullword ascii /* score: '1.00'*/
      $s195 = "`UPxKY" fullword ascii /* score: '1.00'*/
      $s196 = ";{<\"991" fullword ascii /* score: '1.00'*/
      $s197 = "It@I^2Z" fullword ascii /* score: '1.00'*/
      $s198 = "@.=(ly]R" fullword ascii /* score: '1.00'*/
      $s199 = "uw*Q=\\" fullword ascii /* score: '1.00'*/
      $s200 = ">o!R~@" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule sig_78305c8b5e8ead6989a0af09fc6ed8f2ff1b246c0487dfa78fb5b155b554cae9 {
   meta:
      description = "Amadey_MALW - file 78305c8b5e8ead6989a0af09fc6ed8f2ff1b246c0487dfa78fb5b155b554cae9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "78305c8b5e8ead6989a0af09fc6ed8f2ff1b246c0487dfa78fb5b155b554cae9"
   strings:
      $s1 = "mN)R/!!!" fullword ascii /* score: '10.00'*/
      $s2 = "& l* -/ 63 " fullword ascii /* score: '9.00'*/
      $s3 = "qLDLLLD|" fullword ascii /* score: '9.00'*/
      $s4 = "qgghuozc" fullword ascii /* score: '8.00'*/
      $s5 = "qzeqbxes" fullword ascii /* score: '8.00'*/
      $s6 = "\"USER32.8dl" fullword ascii /* score: '7.00'*/
      $s7 = ":<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s8 = "PQRSUVW" fullword ascii /* score: '6.50'*/
      $s9 = "- H'e=" fullword ascii /* score: '5.00'*/
      $s10 = "OFVUTs6" fullword ascii /* score: '5.00'*/
      $s11 = ".* @ih," fullword ascii /* score: '5.00'*/
      $s12 = "%teQ%j" fullword ascii /* score: '5.00'*/
      $s13 = " /o-yIk" fullword ascii /* score: '5.00'*/
      $s14 = "K'-F -1" fullword ascii /* score: '5.00'*/
      $s15 = "%YXfL%)" fullword ascii /* score: '5.00'*/
      $s16 = "g /le`" fullword ascii /* score: '5.00'*/
      $s17 = "%Ex%L7J" fullword ascii /* score: '5.00'*/
      $s18 = "qEiDYr4" fullword ascii /* score: '5.00'*/
      $s19 = "r,- Pl" fullword ascii /* score: '5.00'*/
      $s20 = "P5@@ -" fullword ascii /* score: '5.00'*/
      $s21 = "5L -^c" fullword ascii /* score: '5.00'*/
      $s22 = "+ ]&6_" fullword ascii /* score: '5.00'*/
      $s23 = "\"?'- e" fullword ascii /* score: '5.00'*/
      $s24 = "A- q3d" fullword ascii /* score: '5.00'*/
      $s25 = "-  81S" fullword ascii /* score: '5.00'*/
      $s26 = "ej* 0M!?1" fullword ascii /* score: '5.00'*/
      $s27 = "6ew* t\"" fullword ascii /* score: '5.00'*/
      $s28 = "xiFymdz" fullword ascii /* score: '4.00'*/
      $s29 = "hdbD&c>!" fullword ascii /* score: '4.00'*/
      $s30 = "nbal\"!" fullword ascii /* score: '4.00'*/
      $s31 = "FSDlF;e" fullword ascii /* score: '4.00'*/
      $s32 = "TZUh1!3" fullword ascii /* score: '4.00'*/
      $s33 = "ption I" fullword ascii /* score: '4.00'*/
      $s34 = "ITNLo/6" fullword ascii /* score: '4.00'*/
      $s35 = "pjvkO!" fullword ascii /* score: '4.00'*/
      $s36 = "ADpf')3\\" fullword ascii /* score: '4.00'*/
      $s37 = "UxLHiv>" fullword ascii /* score: '4.00'*/
      $s38 = "iUdRU^}" fullword ascii /* score: '4.00'*/
      $s39 = "kXun0>f" fullword ascii /* score: '4.00'*/
      $s40 = "`tePL$@t%" fullword ascii /* score: '4.00'*/
      $s41 = "#.IyL,3" fullword ascii /* score: '4.00'*/
      $s42 = "\"BhhT&w$" fullword ascii /* score: '4.00'*/
      $s43 = "MDEHkMk" fullword ascii /* score: '4.00'*/
      $s44 = "ILyTcIz{" fullword ascii /* score: '4.00'*/
      $s45 = "8DraeE |" fullword ascii /* score: '4.00'*/
      $s46 = "WfPtD$)N" fullword ascii /* score: '4.00'*/
      $s47 = "&(GrBAQ1e" fullword ascii /* score: '4.00'*/
      $s48 = "%WChwfH)" fullword ascii /* score: '4.00'*/
      $s49 = "Q;`].jpi" fullword ascii /* score: '4.00'*/
      $s50 = "duCr?Oi" fullword ascii /* score: '4.00'*/
      $s51 = "hdrcj\\" fullword ascii /* score: '4.00'*/
      $s52 = "gOMH?a" fullword ascii /* score: '4.00'*/
      $s53 = "vTYm4$AT" fullword ascii /* score: '4.00'*/
      $s54 = "6`*\"ydBX|PP" fullword ascii /* score: '4.00'*/
      $s55 = "fBnJ()c" fullword ascii /* score: '4.00'*/
      $s56 = "pxYa(3X\"e" fullword ascii /* score: '4.00'*/
      $s57 = ".ezXdJJ[" fullword ascii /* score: '4.00'*/
      $s58 = "Zwwot{1" fullword ascii /* score: '4.00'*/
      $s59 = "VIBS=uy5K" fullword ascii /* score: '4.00'*/
      $s60 = "fgEq$IQ" fullword ascii /* score: '4.00'*/
      $s61 = "XUsZ?\\" fullword ascii /* score: '4.00'*/
      $s62 = "tGxexw|Q|k" fullword ascii /* score: '4.00'*/
      $s63 = "a4PtcQ!" fullword ascii /* score: '4.00'*/
      $s64 = "YUUeI'{3" fullword ascii /* score: '4.00'*/
      $s65 = "`HnbJG@t`" fullword ascii /* score: '4.00'*/
      $s66 = "@[2(VnJNj  z" fullword ascii /* score: '4.00'*/
      $s67 = "J tNvA%@)" fullword ascii /* score: '4.00'*/
      $s68 = "IpLw?J" fullword ascii /* score: '4.00'*/
      $s69 = "maJxB!" fullword ascii /* score: '4.00'*/
      $s70 = "tStzxKg" fullword ascii /* score: '4.00'*/
      $s71 = "NEtc\\T." fullword ascii /* score: '4.00'*/
      $s72 = ":HeJH<PB" fullword ascii /* score: '4.00'*/
      $s73 = "UwSPm<o" fullword ascii /* score: '4.00'*/
      $s74 = "VYbf)|HiwY" fullword ascii /* score: '4.00'*/
      $s75 = "TXepY8%" fullword ascii /* score: '4.00'*/
      $s76 = "zthDdOy" fullword ascii /* score: '4.00'*/
      $s77 = "@]vrZbaV&" fullword ascii /* score: '4.00'*/
      $s78 = "`RPXNZ :/" fullword ascii /* score: '4.00'*/
      $s79 = "WlnS]PX" fullword ascii /* score: '4.00'*/
      $s80 = "U(X.QNw" fullword ascii /* score: '4.00'*/
      $s81 = "-w.XGG" fullword ascii /* score: '4.00'*/
      $s82 = "AaswaF^[`[" fullword ascii /* score: '4.00'*/
      $s83 = "mVbI*s'" fullword ascii /* score: '4.00'*/
      $s84 = "SiRWY;KWg" fullword ascii /* score: '4.00'*/
      $s85 = "??%-$NsnfFIq" fullword ascii /* score: '4.00'*/
      $s86 = "\"VDrW~zYf" fullword ascii /* score: '4.00'*/
      $s87 = "OiwBg}|" fullword ascii /* score: '4.00'*/
      $s88 = ".8otas+SA" fullword ascii /* score: '4.00'*/
      $s89 = "zVLfW%3" fullword ascii /* score: '4.00'*/
      $s90 = "jY\\XjWt[ElPMy_" fullword ascii /* score: '4.00'*/
      $s91 = "HRlZH5$\"!" fullword ascii /* score: '4.00'*/
      $s92 = "`QHjq]r_" fullword ascii /* score: '4.00'*/
      $s93 = "rcZX &`" fullword ascii /* score: '4.00'*/
      $s94 = "UwVqZ}\\" fullword ascii /* score: '4.00'*/
      $s95 = "aLzh>P`l!8" fullword ascii /* score: '4.00'*/
      $s96 = "KSvaL!" fullword ascii /* score: '4.00'*/
      $s97 = "hctxmz,K" fullword ascii /* score: '4.00'*/
      $s98 = "tjtVxq|" fullword ascii /* score: '4.00'*/
      $s99 = "dmPwGyF" fullword ascii /* score: '4.00'*/
      $s100 = "JWLxI(k?:Y" fullword ascii /* score: '4.00'*/
      $s101 = "xutG|exw|U|g" fullword ascii /* score: '4.00'*/
      $s102 = "AsdLv\\" fullword ascii /* score: '4.00'*/
      $s103 = "hapR,%\\" fullword ascii /* score: '4.00'*/
      $s104 = "0YwIUj_w^+el" fullword ascii /* score: '4.00'*/
      $s105 = ">]vDyr?t" fullword ascii /* score: '4.00'*/
      $s106 = "qitg}D[kg" fullword ascii /* score: '4.00'*/
      $s107 = "<+hOq.xfQ" fullword ascii /* score: '4.00'*/
      $s108 = "_E)%s4%" fullword ascii /* score: '4.00'*/
      $s109 = "\"RGHu]Ds" fullword ascii /* score: '4.00'*/
      $s110 = "VxFL8`i" fullword ascii /* score: '4.00'*/
      $s111 = "8>wJJzDKJ2" fullword ascii /* score: '4.00'*/
      $s112 = "YSjB-0Y" fullword ascii /* score: '4.00'*/
      $s113 = "GpeR))@" fullword ascii /* score: '4.00'*/
      $s114 = "MxGnSkz" fullword ascii /* score: '4.00'*/
      $s115 = "H!cxiC?R" fullword ascii /* score: '4.00'*/
      $s116 = "kFrY+Tb" fullword ascii /* score: '4.00'*/
      $s117 = "tIuSl!" fullword ascii /* score: '4.00'*/
      $s118 = "MdvmH!W" fullword ascii /* score: '4.00'*/
      $s119 = "1%D:S|" fullword ascii /* score: '4.00'*/
      $s120 = "oEQH?R;" fullword ascii /* score: '4.00'*/
      $s121 = "0rsHuSkvy" fullword ascii /* score: '4.00'*/
      $s122 = "ToyGV$Nh:d" fullword ascii /* score: '4.00'*/
      $s123 = "xBeB$ft8" fullword ascii /* score: '4.00'*/
      $s124 = "nPhz?B" fullword ascii /* score: '4.00'*/
      $s125 = "bnJb!=" fullword ascii /* score: '4.00'*/
      $s126 = "LHCIt<2" fullword ascii /* score: '4.00'*/
      $s127 = "e1-bRwLI_0D" fullword ascii /* score: '4.00'*/
      $s128 = " .TaP!" fullword ascii /* score: '4.00'*/
      $s129 = "IFQH)5J" fullword ascii /* score: '4.00'*/
      $s130 = "BzoTE`8P" fullword ascii /* score: '4.00'*/
      $s131 = "O-QBmu?" fullword ascii /* score: '4.00'*/
      $s132 = "+%S_ZO" fullword ascii /* score: '4.00'*/
      $s133 = "HhtPKz " fullword ascii /* score: '4.00'*/
      $s134 = "U=.rqQ-Dyb-" fullword ascii /* score: '4.00'*/
      $s135 = "teag0k9" fullword ascii /* score: '4.00'*/
      $s136 = "RSCw'U@" fullword ascii /* score: '4.00'*/
      $s137 = "FfQvdAb" fullword ascii /* score: '4.00'*/
      $s138 = "TmwtNLvx" fullword ascii /* score: '4.00'*/
      $s139 = "FXJWS>K" fullword ascii /* score: '4.00'*/
      $s140 = "[2U0&XAXRXHW" fullword ascii /* score: '4.00'*/
      $s141 = "IfuZ@U>" fullword ascii /* score: '4.00'*/
      $s142 = "t%t9LUDx|E|" fullword ascii /* score: '4.00'*/
      $s143 = "iTMz^F'EV'q" fullword ascii /* score: '4.00'*/
      $s144 = "vPZBW\\2b)" fullword ascii /* score: '4.00'*/
      $s145 = "SlAd> x" fullword ascii /* score: '4.00'*/
      $s146 = "tewA01&(" fullword ascii /* score: '4.00'*/
      $s147 = "_/urNUL!" fullword ascii /* score: '4.00'*/
      $s148 = "@hiYvif>" fullword ascii /* score: '4.00'*/
      $s149 = "LLdlEO'>" fullword ascii /* score: '4.00'*/
      $s150 = "Tilz(32" fullword ascii /* score: '4.00'*/
      $s151 = "bRTw`elX" fullword ascii /* score: '4.00'*/
      $s152 = "%a;Szb7<" fullword ascii /* score: '3.50'*/
      $s153 = "[%v;GF\"`" fullword ascii /* score: '3.50'*/
      $s154 = "XSTVNS" fullword ascii /* score: '3.50'*/
      $s155 = ",*%y-e" fullword ascii /* score: '3.50'*/
      $s156 = "\\d kZ'q" fullword ascii /* score: '2.00'*/
      $s157 = "IKXvs1" fullword ascii /* score: '2.00'*/
      $s158 = "\\-cW|oi" fullword ascii /* score: '2.00'*/
      $s159 = "\\+cXRk" fullword ascii /* score: '2.00'*/
      $s160 = "\\<FDbHc" fullword ascii /* score: '2.00'*/
      $s161 = "\\d3B^fP8W" fullword ascii /* score: '2.00'*/
      $s162 = "\\b7./0`}" fullword ascii /* score: '2.00'*/
      $s163 = "bnFVp7" fullword ascii /* score: '2.00'*/
      $s164 = "\\PM0a>x9" fullword ascii /* score: '2.00'*/
      $s165 = "\\$Wo#g" fullword ascii /* score: '2.00'*/
      $s166 = "\\E!fjS" fullword ascii /* score: '2.00'*/
      $s167 = "\\_/~6{" fullword ascii /* score: '2.00'*/
      $s168 = "1(`ftP" fullword ascii /* score: '2.00'*/
      $s169 = "\\mD7i%" fullword ascii /* score: '2.00'*/
      $s170 = "tRIIi5" fullword ascii /* score: '2.00'*/
      $s171 = "\\#.+ff" fullword ascii /* score: '2.00'*/
      $s172 = "\\c%I; W`" fullword ascii /* score: '2.00'*/
      $s173 = "\\&y50>" fullword ascii /* score: '2.00'*/
      $s174 = "\\Q*;>(" fullword ascii /* score: '2.00'*/
      $s175 = "HGBJ01" fullword ascii /* score: '2.00'*/
      $s176 = "UQxb13" fullword ascii /* score: '2.00'*/
      $s177 = "eSMoy7" fullword ascii /* score: '2.00'*/
      $s178 = "\\MY+B/" fullword ascii /* score: '2.00'*/
      $s179 = "GTCRY8" fullword ascii /* score: '2.00'*/
      $s180 = "RWVqN4" fullword ascii /* score: '2.00'*/
      $s181 = "\\?b3;|,'S" fullword ascii /* score: '2.00'*/
      $s182 = "CShLo6" fullword ascii /* score: '2.00'*/
      $s183 = "\\$|6pM" fullword ascii /* score: '2.00'*/
      $s184 = "WqOYY8" fullword ascii /* score: '2.00'*/
      $s185 = "\\+R]Q]" fullword ascii /* score: '2.00'*/
      $s186 = "LRTKZ5" fullword ascii /* score: '2.00'*/
      $s187 = "\\O%)Ga" fullword ascii /* score: '2.00'*/
      $s188 = "Cyfx80" fullword ascii /* score: '2.00'*/
      $s189 = "\\4}ds;" fullword ascii /* score: '2.00'*/
      $s190 = "\\f@4AJ" fullword ascii /* score: '2.00'*/
      $s191 = "\\Ez\\%i" fullword ascii /* score: '2.00'*/
      $s192 = "KnBpk1" fullword ascii /* score: '2.00'*/
      $s193 = "\\6G)isf" fullword ascii /* score: '2.00'*/
      $s194 = "\\Kb;!@" fullword ascii /* score: '2.00'*/
      $s195 = "\\mE=;7" fullword ascii /* score: '2.00'*/
      $s196 = "\\%81d " fullword ascii /* score: '2.00'*/
      $s197 = "\\_Z2`x" fullword ascii /* score: '2.00'*/
      $s198 = "QbIu27" fullword ascii /* score: '2.00'*/
      $s199 = "tcLeK5" fullword ascii /* score: '2.00'*/
      $s200 = "\\ZZ)9 " fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule d04f0d88706837f7af27edf86b3c0e3241bad8ab43939ddda29dc6541b20eed2 {
   meta:
      description = "Amadey_MALW - file d04f0d88706837f7af27edf86b3c0e3241bad8ab43939ddda29dc6541b20eed2"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "d04f0d88706837f7af27edf86b3c0e3241bad8ab43939ddda29dc6541b20eed2"
   strings:
      $s1 = ":2}=+~0/:" fullword ascii /* score: '9.00'*/ /* hex encoded string ' ' */
      $s2 = ",]@4<0>!%" fullword ascii /* score: '9.00'*/ /* hex encoded string '@' */
      $s3 = "uwljxsff" fullword ascii /* score: '8.00'*/
      $s4 = "kuuhkjxl" fullword ascii /* score: '8.00'*/
      $s5 = "1<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s6 = "PQRSUVW" fullword ascii /* score: '6.50'*/
      $s7 = "TzGeTD" fullword ascii /* score: '6.00'*/
      $s8 = "` %ftP" fullword ascii /* score: '6.00'*/
      $s9 = "9+ QH8^l " fullword ascii /* score: '5.00'*/
      $s10 = ")/g(\" -!" fullword ascii /* score: '5.00'*/
      $s11 = "Je\" /T" fullword ascii /* score: '5.00'*/
      $s12 = "pMoNqg1" fullword ascii /* score: '5.00'*/
      $s13 = "h -2)." fullword ascii /* score: '5.00'*/
      $s14 = "+J- m/+o%1V" fullword ascii /* score: '5.00'*/
      $s15 = "aL+  b" fullword ascii /* score: '5.00'*/
      $s16 = "- E~'}" fullword ascii /* score: '5.00'*/
      $s17 = "stq+ ," fullword ascii /* score: '5.00'*/
      $s18 = "w4=H -" fullword ascii /* score: '5.00'*/
      $s19 = "- Vh/Q" fullword ascii /* score: '5.00'*/
      $s20 = "9;yB- 9" fullword ascii /* score: '5.00'*/
      $s21 = "\\1NIDd$ `" fullword ascii /* score: '5.00'*/
      $s22 = "+ |o$}" fullword ascii /* score: '5.00'*/
      $s23 = "Rn%D0- a" fullword ascii /* score: '5.00'*/
      $s24 = ")le -(" fullword ascii /* score: '5.00'*/
      $s25 = "PKS -." fullword ascii /* score: '5.00'*/
      $s26 = "'- 9@h?)G+" fullword ascii /* score: '5.00'*/
      $s27 = "Mzc%v%" fullword ascii /* score: '5.00'*/
      $s28 = " /fXRN" fullword ascii /* score: '5.00'*/
      $s29 = ":{Ro- @b" fullword ascii /* score: '5.00'*/
      $s30 = "RRf_- " fullword ascii /* score: '5.00'*/
      $s31 = "@y+- N[" fullword ascii /* score: '5.00'*/
      $s32 = "QCIJ~}S" fullword ascii /* score: '4.00'*/
      $s33 = "mPXfQ1Y" fullword ascii /* score: '4.00'*/
      $s34 = "?,jZwF\"O" fullword ascii /* score: '4.00'*/
      $s35 = "bLRR-:'" fullword ascii /* score: '4.00'*/
      $s36 = "VpDK=<K<" fullword ascii /* score: '4.00'*/
      $s37 = "Zhey/Vk" fullword ascii /* score: '4.00'*/
      $s38 = "bXcFd~0" fullword ascii /* score: '4.00'*/
      $s39 = "anRp,T$" fullword ascii /* score: '4.00'*/
      $s40 = "rPLh>#yC" fullword ascii /* score: '4.00'*/
      $s41 = "4o;&?.TAM" fullword ascii /* score: '4.00'*/
      $s42 = " mpjf%&\"" fullword ascii /* score: '4.00'*/
      $s43 = "GRAAb\\" fullword ascii /* score: '4.00'*/
      $s44 = "4dOhUaEg" fullword ascii /* score: '4.00'*/
      $s45 = ".?SqLB\"Z" fullword ascii /* score: '4.00'*/
      $s46 = "lkyH\\%" fullword ascii /* score: '4.00'*/
      $s47 = ")q(eNqK!" fullword ascii /* score: '4.00'*/
      $s48 = "bShuxd_[A@B)" fullword ascii /* score: '4.00'*/
      $s49 = "vpiwP?" fullword ascii /* score: '4.00'*/
      $s50 = "yDiWc3N" fullword ascii /* score: '4.00'*/
      $s51 = "xihxBd@" fullword ascii /* score: '4.00'*/
      $s52 = "d:PoDN!@" fullword ascii /* score: '4.00'*/
      $s53 = "iVjGevY" fullword ascii /* score: '4.00'*/
      $s54 = "EKLh{X(" fullword ascii /* score: '4.00'*/
      $s55 = "QhlaxK:" fullword ascii /* score: '4.00'*/
      $s56 = "kaXS!\\" fullword ascii /* score: '4.00'*/
      $s57 = "KouGLzU" fullword ascii /* score: '4.00'*/
      $s58 = "GWVXrYM" fullword ascii /* score: '4.00'*/
      $s59 = "JdZuACr*" fullword ascii /* score: '4.00'*/
      $s60 = "?BkYs@/vG`" fullword ascii /* score: '4.00'*/
      $s61 = "bxttO&a0" fullword ascii /* score: '4.00'*/
      $s62 = "z.KER/w)" fullword ascii /* score: '4.00'*/
      $s63 = "brPEl't" fullword ascii /* score: '4.00'*/
      $s64 = "peqD`1t" fullword ascii /* score: '4.00'*/
      $s65 = "IbhyT9%d" fullword ascii /* score: '4.00'*/
      $s66 = "idxP8L{" fullword ascii /* score: '4.00'*/
      $s67 = "Gyqkcz?" fullword ascii /* score: '4.00'*/
      $s68 = "tAozT}v" fullword ascii /* score: '4.00'*/
      $s69 = "xQytkMm" fullword ascii /* score: '4.00'*/
      $s70 = "VIRJiTN" fullword ascii /* score: '4.00'*/
      $s71 = "0vubd_tGZH{" fullword ascii /* score: '4.00'*/
      $s72 = "cUtbD_z" fullword ascii /* score: '4.00'*/
      $s73 = "UV.SJT(" fullword ascii /* score: '4.00'*/
      $s74 = "ORTHj:0" fullword ascii /* score: '4.00'*/
      $s75 = "!TqLT3<r" fullword ascii /* score: '4.00'*/
      $s76 = "(NTdL@Qp" fullword ascii /* score: '4.00'*/
      $s77 = "XcXgXcr" fullword ascii /* score: '4.00'*/
      $s78 = "BqPHX>.TZ" fullword ascii /* score: '4.00'*/
      $s79 = "nQfe+V|" fullword ascii /* score: '4.00'*/
      $s80 = ">OVCDxUh" fullword ascii /* score: '4.00'*/
      $s81 = "TzIP@\\+" fullword ascii /* score: '4.00'*/
      $s82 = "AhFmVoB" fullword ascii /* score: '4.00'*/
      $s83 = "B|TwyH}!0[hl?" fullword ascii /* score: '4.00'*/
      $s84 = "hslHdhN" fullword ascii /* score: '4.00'*/
      $s85 = "(VeRS5>PEX" fullword ascii /* score: '4.00'*/
      $s86 = "gMXS)[2" fullword ascii /* score: '4.00'*/
      $s87 = "VLkz(JZ" fullword ascii /* score: '4.00'*/
      $s88 = "G.bSa f" fullword ascii /* score: '4.00'*/
      $s89 = "iRjC}_W" fullword ascii /* score: '4.00'*/
      $s90 = "3:.Vid-" fullword ascii /* score: '4.00'*/
      $s91 = "SOCm^(?" fullword ascii /* score: '4.00'*/
      $s92 = "zwit@k)_" fullword ascii /* score: '4.00'*/
      $s93 = "akSQvKsf" fullword ascii /* score: '4.00'*/
      $s94 = "UqGH%\"" fullword ascii /* score: '4.00'*/
      $s95 = ".H$.wpF" fullword ascii /* score: '4.00'*/
      $s96 = "JnUy@/?_" fullword ascii /* score: '4.00'*/
      $s97 = "lBRch q" fullword ascii /* score: '4.00'*/
      $s98 = "%pnsL:D>" fullword ascii /* score: '4.00'*/
      $s99 = "oweekSm" fullword ascii /* score: '4.00'*/
      $s100 = "qGwa?\\" fullword ascii /* score: '4.00'*/
      $s101 = "XFDmE,6dR" fullword ascii /* score: '4.00'*/
      $s102 = "$NEsb!" fullword ascii /* score: '4.00'*/
      $s103 = "8<+2PWjH`P*" fullword ascii /* score: '4.00'*/
      $s104 = "i@~WQcM8NjN" fullword ascii /* score: '4.00'*/
      $s105 = "v(.gxT" fullword ascii /* score: '4.00'*/
      $s106 = "Drgd%t/" fullword ascii /* score: '4.00'*/
      $s107 = "ZtStG?^" fullword ascii /* score: '4.00'*/
      $s108 = "MdxJI\"" fullword ascii /* score: '4.00'*/
      $s109 = "-l DgEzSLD" fullword ascii /* score: '4.00'*/
      $s110 = "gxjH|&c(p$" fullword ascii /* score: '4.00'*/
      $s111 = "bVwe0'F" fullword ascii /* score: '4.00'*/
      $s112 = "AtEX |r" fullword ascii /* score: '4.00'*/
      $s113 = "H^.bqc{" fullword ascii /* score: '4.00'*/
      $s114 = "vWKRB`HTt^" fullword ascii /* score: '4.00'*/
      $s115 = "BBTA6ZD" fullword ascii /* score: '4.00'*/
      $s116 = "ZVjQ2UA" fullword ascii /* score: '4.00'*/
      $s117 = "uTwu!<" fullword ascii /* score: '4.00'*/
      $s118 = "iZpLs\\" fullword ascii /* score: '4.00'*/
      $s119 = "QTSXV,PQtd" fullword ascii /* score: '4.00'*/
      $s120 = "kTvR\\'I" fullword ascii /* score: '4.00'*/
      $s121 = "qImg4^;" fullword ascii /* score: '4.00'*/
      $s122 = "vpRV)I}" fullword ascii /* score: '4.00'*/
      $s123 = "l/GHwc0vp!" fullword ascii /* score: '4.00'*/
      $s124 = "AaQIT_5k&" fullword ascii /* score: '4.00'*/
      $s125 = "zULn_})" fullword ascii /* score: '4.00'*/
      $s126 = "zDlpAq;14^" fullword ascii /* score: '4.00'*/
      $s127 = "Pwnq&#9g" fullword ascii /* score: '4.00'*/
      $s128 = "giewQrE" fullword ascii /* score: '4.00'*/
      $s129 = "IwQjIfhH" fullword ascii /* score: '4.00'*/
      $s130 = ".mUM> )Z" fullword ascii /* score: '4.00'*/
      $s131 = "-LqZj)>." fullword ascii /* score: '4.00'*/
      $s132 = "gewhe\"D" fullword ascii /* score: '4.00'*/
      $s133 = "0XaWT_SUrh7" fullword ascii /* score: '4.00'*/
      $s134 = "XTmke!" fullword ascii /* score: '4.00'*/
      $s135 = "oczj&_Z" fullword ascii /* score: '4.00'*/
      $s136 = "_G:MtCt'x x" fullword ascii /* score: '4.00'*/
      $s137 = "pMIP\"H" fullword ascii /* score: '4.00'*/
      $s138 = "bUGc$t'" fullword ascii /* score: '4.00'*/
      $s139 = "uqgk}:a" fullword ascii /* score: '4.00'*/
      $s140 = "yjGIy,z" fullword ascii /* score: '4.00'*/
      $s141 = "hKcd e;" fullword ascii /* score: '4.00'*/
      $s142 = "hmuOD-x" fullword ascii /* score: '4.00'*/
      $s143 = "lEivXFM" fullword ascii /* score: '4.00'*/
      $s144 = "FKoeU!n." fullword ascii /* score: '4.00'*/
      $s145 = "JsDj\\1" fullword ascii /* score: '4.00'*/
      $s146 = "AOgT!9" fullword ascii /* score: '4.00'*/
      $s147 = "vexr6gEyd" fullword ascii /* score: '4.00'*/
      $s148 = ".YAh/!P" fullword ascii /* score: '4.00'*/
      $s149 = "*XiNx|cf" fullword ascii /* score: '4.00'*/
      $s150 = "^jblV\\c" fullword ascii /* score: '4.00'*/
      $s151 = "\\@[)ul" fullword ascii /* score: '2.00'*/
      $s152 = "\\jRbU2" fullword ascii /* score: '2.00'*/
      $s153 = "\\1|%'~" fullword ascii /* score: '2.00'*/
      $s154 = "\\@OR3L" fullword ascii /* score: '2.00'*/
      $s155 = "QJfge0" fullword ascii /* score: '2.00'*/
      $s156 = "\\4 \"~e" fullword ascii /* score: '2.00'*/
      $s157 = "\\&it\\T" fullword ascii /* score: '2.00'*/
      $s158 = "\\H`\"%P" fullword ascii /* score: '2.00'*/
      $s159 = "\\e%$l$" fullword ascii /* score: '2.00'*/
      $s160 = "\\;RTN-" fullword ascii /* score: '2.00'*/
      $s161 = "iWHGZ1" fullword ascii /* score: '2.00'*/
      $s162 = "\\PR8ePX" fullword ascii /* score: '2.00'*/
      $s163 = "LIKu55" fullword ascii /* score: '2.00'*/
      $s164 = "\\(qX}@" fullword ascii /* score: '2.00'*/
      $s165 = "\\u1U})" fullword ascii /* score: '2.00'*/
      $s166 = "\\Av|0]" fullword ascii /* score: '2.00'*/
      $s167 = "PFcO91" fullword ascii /* score: '2.00'*/
      $s168 = "\\%V!#p" fullword ascii /* score: '2.00'*/
      $s169 = "\\}q6 8" fullword ascii /* score: '2.00'*/
      $s170 = "\\R*$k%" fullword ascii /* score: '2.00'*/
      $s171 = "\\K20TsY" fullword ascii /* score: '2.00'*/
      $s172 = "IWQPH0" fullword ascii /* score: '2.00'*/
      $s173 = "\\U`Rq*" fullword ascii /* score: '2.00'*/
      $s174 = "\\}F{5p" fullword ascii /* score: '2.00'*/
      $s175 = "BHALR1" fullword ascii /* score: '2.00'*/
      $s176 = "\\KZ}j)" fullword ascii /* score: '2.00'*/
      $s177 = "BhqHJ0" fullword ascii /* score: '2.00'*/
      $s178 = "\\'lo0L" fullword ascii /* score: '2.00'*/
      $s179 = "zYXKh6" fullword ascii /* score: '2.00'*/
      $s180 = "\\F1@&RS" fullword ascii /* score: '2.00'*/
      $s181 = "\\.Zv!k" fullword ascii /* score: '2.00'*/
      $s182 = "\\7H|sT" fullword ascii /* score: '2.00'*/
      $s183 = "\\U/:dVe%L" fullword ascii /* score: '2.00'*/
      $s184 = "\\~GX4@" fullword ascii /* score: '2.00'*/
      $s185 = "UTqSN3" fullword ascii /* score: '2.00'*/
      $s186 = "\\^\"bYU" fullword ascii /* score: '2.00'*/
      $s187 = "\\{X+;()" fullword ascii /* score: '2.00'*/
      $s188 = "\\5AHUX," fullword ascii /* score: '2.00'*/
      $s189 = "\\V%T^vy" fullword ascii /* score: '2.00'*/
      $s190 = ")3Kc/3" fullword ascii /* score: '1.00'*/
      $s191 = "^][ZYX" fullword ascii /* score: '1.00'*/
      $s192 = "XBH_FNpT" fullword ascii /* score: '1.00'*/
      $s193 = "#EOX<xO" fullword ascii /* score: '1.00'*/
      $s194 = "S=>43>" fullword ascii /* score: '1.00'*/
      $s195 = "WXZ_)P{G" fullword ascii /* score: '1.00'*/
      $s196 = "8'9;WN" fullword ascii /* score: '1.00'*/
      $s197 = "@AOX*h" fullword ascii /* score: '1.00'*/
      $s198 = ">~itpp" fullword ascii /* score: '1.00'*/
      $s199 = "wx|b`*y" fullword ascii /* score: '1.00'*/
      $s200 = " _3>1J" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae {
   meta:
      description = "Amadey_MALW - file fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae"
   strings:
      $s1 = "Oi8vcGtpLWNybC5zeW1hdXRoLmNvbS9vZmZsaW5lY2EvVGhlSW5zdGl0dXRlb2ZF" fullword ascii /* base64 encoded string '://pki-crl.symauth.com/offlineca/TheInstituteofE' */ /* score: '14.00'*/
      $s2 = "bGVjdHJpY2FsYW5kRWxlY3Ryb25pY3NFbmdpbmVlcnNJbmNJRUVFUm9vdENBLmNy" fullword ascii /* base64 encoded string 'lectricalandElectronicsEngineersIncIEEERootCA.cr' */ /* score: '14.00'*/
      $s3 = "KgI8WCsKbA0ZGeThc1GC7WN3kYdWRXtU2S+auJHMpA17DJMyNmsn7DAC2QKBgDb3" fullword ascii /* score: '9.00'*/
      $s4 = "Y2FsIGFuZCBFbGVjdHJvbmljcyBFbmdpbmVlcnMsIEluYy4xDTALBgNVBAsTBElF" fullword ascii /* score: '9.00'*/
      $s5 = "NzAzMTAyMzU5NTlaMDIxEjAQBgNVBAMMCU9SX0syRDlLTzEcMBoGA1UECgwTT3Jl" fullword ascii /* score: '9.00'*/
      $s6 = "Dc|*SPYw|x(" fullword ascii /* score: '9.00'*/
      $s7 = "* TTdL{C" fullword ascii /* score: '9.00'*/
      $s8 = "zVze+ q" fullword ascii /* score: '8.00'*/
      $s9 = "wokugkrf" fullword ascii /* score: '8.00'*/
      $s10 = "PUSER32" fullword ascii /* score: '8.00'*/
      $s11 = "lq%IXRQ%S`:" fullword ascii /* score: '8.00'*/
      $s12 = "csqdmnjl" fullword ascii /* score: '8.00'*/
      $s13 = "0DRG:\\" fullword ascii /* score: '7.00'*/
      $s14 = "5<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s15 = "9CL9pu5C0z4kJyfSMwM2runHEz99FQYE4rJ5ZBC3QW/BBSF50eTYo8ms2pyD/XdW" fullword ascii /* score: '7.00'*/
      $s16 = "PQRSUVW" fullword ascii /* score: '6.50'*/
      $s17 = "ADVePI1" fullword ascii /* score: '5.00'*/
      $s18 = "nhDppe7" fullword ascii /* score: '5.00'*/
      $s19 = "& + 1!" fullword ascii /* score: '5.00'*/
      $s20 = "- J-wq[" fullword ascii /* score: '5.00'*/
      $s21 = "w- 26]{o')" fullword ascii /* score: '5.00'*/
      $s22 = "\\wEHyB/hR" fullword ascii /* score: '5.00'*/
      $s23 = " U% :+ " fullword ascii /* score: '5.00'*/
      $s24 = "4ofA9+ @" fullword ascii /* score: '5.00'*/
      $s25 = "}Rq -w" fullword ascii /* score: '5.00'*/
      $s26 = "5- ez$ " fullword ascii /* score: '5.00'*/
      $s27 = "R+ Wi#" fullword ascii /* score: '5.00'*/
      $s28 = "% B* j. E1 " fullword ascii /* score: '5.00'*/
      $s29 = ":- E:(3N-" fullword ascii /* score: '5.00'*/
      $s30 = "xJ- `[p" fullword ascii /* score: '5.00'*/
      $s31 = "y]%T%%" fullword ascii /* score: '5.00'*/
      $s32 = ")?d9* " fullword ascii /* score: '5.00'*/
      $s33 = "bDtS8&H" fullword ascii /* score: '4.00'*/
      $s34 = "<.dgf*" fullword ascii /* score: '4.00'*/
      $s35 = "nWMa:%H$$<" fullword ascii /* score: '4.00'*/
      $s36 = "JpjQ`\\" fullword ascii /* score: '4.00'*/
      $s37 = "AhLitnJEkZp978TgqR93e6P3wuKwjEvti1inwQlIN1CkMzX79NtUPwd1+eHjEShJ" fullword ascii /* score: '4.00'*/
      $s38 = "D8.LGU" fullword ascii /* score: '4.00'*/
      $s39 = "nGVYqz^f" fullword ascii /* score: '4.00'*/
      $s40 = "tFQP?O" fullword ascii /* score: '4.00'*/
      $s41 = "qr7sDe6vMGn+HkYPsx1+uLWm45WKe+f5oVeHuNpG0r8irF5WLqtOOmcTkC9LaiTQ" fullword ascii /* score: '4.00'*/
      $s42 = "TE9HSUVTMR8wHQYDVQQDExZPUkVBTlMgVEVDSE5PTE9HSUVTIENBMIIBIjANBgkq" fullword ascii /* score: '4.00'*/
      $s43 = "RUUxFTATBgNVBAMTDElFRUUgUm9vdCBDQTAeFw0xMzA0MzAwMDAwMDBaFw0zMzA0" fullword ascii /* score: '4.00'*/
      $s44 = "gG0Vz4Dd3xKWz7eAXksruuaOQ5V+HIrNTB03hJHJ84Wr/Gmo+NLgXXGYxjR0nff8" fullword ascii /* score: '4.00'*/
      $s45 = "WVcsEKu" fullword ascii /* score: '4.00'*/
      $s46 = "^b#lBIm9;F" fullword ascii /* score: '4.00'*/
      $s47 = "pWqNRwC/fdS+9MOO+JgsHUKR6wqNgpiBNR5uo6sJyqrAZKIUf+DCrEfUMPcxDy3a" fullword ascii /* score: '4.00'*/
      $s48 = "YXAz%0/(" fullword ascii /* score: '4.00'*/
      $s49 = "-PaCK$Po" fullword ascii /* score: '4.00'*/
      $s50 = "GFEJ!r" fullword ascii /* score: '4.00'*/
      $s51 = "hmiaL{7" fullword ascii /* score: '4.00'*/
      $s52 = "taRp;\"" fullword ascii /* score: '4.00'*/
      $s53 = "P_.ETT" fullword ascii /* score: '4.00'*/
      $s54 = "MdCWN|Y}" fullword ascii /* score: '4.00'*/
      $s55 = "<xUvdtb<f" fullword ascii /* score: '4.00'*/
      $s56 = "9ZenTPfw7DJdHTNjANBgkqhkiG9w0BAQsFADB5" fullword ascii /* score: '4.00'*/
      $s57 = "AKMdAU6Fg625afTnyJ5okcuO+rYslG/ALM/mYH4c272Y68bUT26+US6atny2DdId" fullword ascii /* score: '4.00'*/
      $s58 = "vggMRJd" fullword ascii /* score: '4.00'*/
      $s59 = "Nhig!7" fullword ascii /* score: '4.00'*/
      $s60 = "KZLp?<" fullword ascii /* score: '4.00'*/
      $s61 = "DwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjBdBgNVHR8EVjBUMFKgUKBO" fullword ascii /* score: '4.00'*/
      $s62 = "hLDoT@^g" fullword ascii /* score: '4.00'*/
      $s63 = ".iFJ,!" fullword ascii /* score: '4.00'*/
      $s64 = "lVhIY,F" fullword ascii /* score: '4.00'*/
      $s65 = "<KvtZBW}" fullword ascii /* score: '4.00'*/
      $s66 = "AMYz/YccDiRS0IyNv4vkg0uH+GTP0a9m529iNMbn5pqcvyGiAcngZ0QT8tsvdU18" fullword ascii /* score: '4.00'*/
      $s67 = "QAKz/P\\" fullword ascii /* score: '4.00'*/
      $s68 = "?[MbJI\":" fullword ascii /* score: '4.00'*/
      $s69 = "5rz6joWZgd53/w6QVc7L0L7lIOzOniL/BsW+1ak8dwbaZPPPbLflz4MNWgMw1dGw" fullword ascii /* score: '4.00'*/
      $s70 = "YplL!N" fullword ascii /* score: '4.00'*/
      $s71 = "Y`BBqG?a" fullword ascii /* score: '4.00'*/
      $s72 = "SGkfr%S[" fullword ascii /* score: '4.00'*/
      $s73 = "qaMyHLR:t" fullword ascii /* score: '4.00'*/
      $s74 = "FkwhAA0XigWIIf2SWA0Q4bERNhQt4pMVa6va6FcVLWJ3/0hvndAUVO4p8OwMLSHT" fullword ascii /* score: '4.00'*/
      $s75 = "3pUtcCOFe9q8+/kDOo40Bvk=" fullword ascii /* score: '4.00'*/
      $s76 = "qUsL~e3" fullword ascii /* score: '4.00'*/
      $s77 = "fLZV.^+" fullword ascii /* score: '4.00'*/
      $s78 = "pvlA!H" fullword ascii /* score: '4.00'*/
      $s79 = "QpLdBa$f0i" fullword ascii /* score: '4.00'*/
      $s80 = "sJXhnhntM5tdEkawRhgXIi9ONb4gXoW32ECgmvWixmiTOEejJTph5kluOgRRoKSp" fullword ascii /* score: '4.00'*/
      $s81 = "XVKd '+" fullword ascii /* score: '4.00'*/
      $s82 = "Uh98dhlTDJPXgtKTGYGhfAxGR3UYdXjbV+sIn/tK8UTa3pW51nKLfez0iGVvGr6i" fullword ascii /* score: '4.00'*/
      $s83 = "LbAx Ik$" fullword ascii /* score: '4.00'*/
      $s84 = "xmbBdNf" fullword ascii /* score: '4.00'*/
      $s85 = "MBaAFBD/fnNAyNAvjtZvtTIhFEAnbpXEMA0GCSqGSIb3DQEBCwUAA4IBAQAENAj6" fullword ascii /* score: '4.00'*/
      $s86 = "sKlj|\\" fullword ascii /* score: '4.00'*/
      $s87 = "uJRVix`" fullword ascii /* score: '4.00'*/
      $s88 = "VhYokeL" fullword ascii /* score: '4.00'*/
      $s89 = "u5Xjtn!u" fullword ascii /* score: '4.00'*/
      $s90 = "-)ULYAP s z" fullword ascii /* score: '4.00'*/
      $s91 = "(7QBYN+ik" fullword ascii /* score: '4.00'*/
      $s92 = "=lzwuDA@A" fullword ascii /* score: '4.00'*/
      $s93 = "A1UEAxMWT1JFQU5TIFRFQ0hOT0xPR0lFUyBDQTAeFw0xNzAzMTIwMDAwMDBaFw0y" fullword ascii /* score: '4.00'*/
      $s94 = "iUdXTT*" fullword ascii /* score: '4.00'*/
      $s95 = "tiRTM$Rb1" fullword ascii /* score: '4.00'*/
      $s96 = "8FnpH79%" fullword ascii /* score: '4.00'*/
      $s97 = "kq04pWNhL|t" fullword ascii /* score: '4.00'*/
      $s98 = "v.Hdf/" fullword ascii /* score: '4.00'*/
      $s99 = "MQswCQYDVQQGEwJTUDEcMBoGA1UEChMTT1JFQU5TIFRFQ0hOT0xPR0lFUzEfMB0G" fullword ascii /* score: '4.00'*/
      $s100 = "?BOVC\"\\" fullword ascii /* score: '4.00'*/
      $s101 = "AJBu5TZPLM2rIwFqgao+1fJFMB8r5sFSwsdipXqdsfIJCSHBwSBO+bitPX+um5Xd" fullword ascii /* score: '4.00'*/
      $s102 = "QhFI%.," fullword ascii /* score: '4.00'*/
      $s103 = "pMYITLb" fullword ascii /* score: '4.00'*/
      $s104 = "t9ZVNB!" fullword ascii /* score: '4.00'*/
      $s105 = "~CfIp?" fullword ascii /* score: '4.00'*/
      $s106 = "hnDs'Wr" fullword ascii /* score: '4.00'*/
      $s107 = "iuFxOX){" fullword ascii /* score: '4.00'*/
      $s108 = "RAIO\\e;" fullword ascii /* score: '4.00'*/
      $s109 = "_vSQan)Ro" fullword ascii /* score: '4.00'*/
      $s110 = "BggrBgEFBQcwAYYbaHR0cDovL3BraS1vY3NwLnN5bWF1dGguY29tMB8GA1UdIwQY" fullword ascii /* score: '4.00'*/
      $s111 = "^esHbg/5" fullword ascii /* score: '4.00'*/
      $s112 = "RSYP?X" fullword ascii /* score: '4.00'*/
      $s113 = "7kpLcSDavDAg6wQ1dAOcpqwRzkbI/EZ8uaEG475VhfnfmZc7Ly6nIxb7eONSSW/j" fullword ascii /* score: '4.00'*/
      $s114 = "2cbyZg!" fullword ascii /* score: '4.00'*/
      $s115 = "lmPk<)5" fullword ascii /* score: '4.00'*/
      $s116 = "biVDpDPI" fullword ascii /* score: '4.00'*/
      $s117 = "aUBxe F" fullword ascii /* score: '4.00'*/
      $s118 = "MYYS\\t" fullword ascii /* score: '4.00'*/
      $s119 = "fXHuXdR" fullword ascii /* score: '4.00'*/
      $s120 = "(V.RWz" fullword ascii /* score: '4.00'*/
      $s121 = "efGnA1g5Qm0FWbnB2rjEXryZoc/QD2CsqBI436xeR>" fullword ascii /* score: '4.00'*/
      $s122 = "qTXSh'u" fullword ascii /* score: '4.00'*/
      $s123 = "WOSqX8QDj" fullword ascii /* score: '4.00'*/
      $s124 = "gbJL0? iS" fullword ascii /* score: '4.00'*/
      $s125 = "LjlaHK!" fullword ascii /* score: '4.00'*/
      $s126 = "[\\NZTSb!" fullword ascii /* score: '4.00'*/
      $s127 = "DIuS` x%+" fullword ascii /* score: '4.00'*/
      $s128 = "MQswCQYDVQQGEwJVUzFEMEIGA1UEChM7VGhlIEluc3RpdHV0ZSBvZiBFbGVjdHJp" fullword ascii /* score: '4.00'*/
      $s129 = "8sZqR!" fullword ascii /* score: '4.00'*/
      $s130 = "DYMVM&w" fullword ascii /* score: '4.00'*/
      $s131 = "QujH%E9" fullword ascii /* score: '4.00'*/
      $s132 = "/owjd6bOUI31nC9OTb2SFEFzw8aNpNraHupEnpKThR7nPQiqYyP9CF9y6ZHlp5HE" fullword ascii /* score: '4.00'*/
      $s133 = "Vhot2p_" fullword ascii /* score: '4.00'*/
      $s134 = "wtiBd`N" fullword ascii /* score: '4.00'*/
      $s135 = "CVPgLe9SBvqTZsYEc7kB9ZenTPfw7G1Kh8XwHBUjK6ejYYtoo84jVPvpRo6rSbh/" fullword ascii /* score: '4.00'*/
      $s136 = "AfSdNM6/46ObIJJmWHHvpVJatiRNgrw836RyE" fullword ascii /* score: '4.00'*/
      $s137 = "vIbPEdvrEdaYM8lRQz3Q9/C7QFrAZcxNuoW1g+zYgmHWmSsl/iL+uFrAvW9MmHD0" fullword ascii /* score: '4.00'*/
      $s138 = "lQSsZV7d/AwmUJN2zJsUYKYULQQYC6nSDvR1gtw0n/Dg2DJezbbOww74y7JWk+Vo" fullword ascii /* score: '4.00'*/
      $s139 = "jWpKZQCG5Ge7qiJ5e/uEQRMaMPugm08JHk6FPFIBAoGAInYh9GkwCUw6Q4gCtzMC" fullword ascii /* score: '4.00'*/
      $s140 = "PVUV5aY^" fullword ascii /* score: '4.00'*/
      $s141 = "aRZQYru\\" fullword ascii /* score: '4.00'*/
      $s142 = "DsJBA{A_" fullword ascii /* score: '4.00'*/
      $s143 = "FiPpyFBvBkSk0WF58acDWDlCbQVZucHauMRevJmhz9APYKyoEjjfrF5FH+jZiW7g" fullword ascii /* score: '4.00'*/
      $s144 = "hkxodHRwOi8vcGtpLWNybC5zeW1hdXRoLmNvbS9jYV9kNDA5YTVjYjczN2RjMDc2" fullword ascii /* score: '4.00'*/
      $s145 = "idPLlDA" fullword ascii /* score: '4.00'*/
      $s146 = "qhkw1% r" fullword ascii /* score: '4.00'*/
      $s147 = "kreJGUmQXQI/FbEEfC7an2CfXxARIPUwn6X0uNWrw9LLy6CBujgCfcEFU88fiWRp" fullword ascii /* score: '4.00'*/
      $s148 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGM/2HHA4kUtCM" fullword ascii /* score: '4.00'*/
      $s149 = "Fzwmm)P" fullword ascii /* score: '4.00'*/
      $s150 = "oKHv6:<Lo" fullword ascii /* score: '4.00'*/
      $s151 = "MjkyMzU5NTlaMEwxCzAJBgNVBAYTAlNQMRwwGgYDVQQKExNPUkVBTlMgVEVDSE5P" fullword ascii /* score: '4.00'*/
      $s152 = "KRUV?1" fullword ascii /* score: '4.00'*/
      $s153 = "BJYWI~Q" fullword ascii /* score: '4.00'*/
      $s154 = "/IFZnf(b9>" fullword ascii /* score: '4.00'*/
      $s155 = "JNvV n*P" fullword ascii /* score: '4.00'*/
      $s156 = "ktDiUY?" fullword ascii /* score: '4.00'*/
      $s157 = "UiueF>'" fullword ascii /* score: '4.00'*/
      $s158 = "ixehN<$" fullword ascii /* score: '4.00'*/
      $s159 = ")dKAhIs?" fullword ascii /* score: '4.00'*/
      $s160 = "qKeN!jA" fullword ascii /* score: '4.00'*/
      $s161 = "YxSV&EjDJ" fullword ascii /* score: '4.00'*/
      $s162 = "LYYxa0K1NkAz6MuY9oJOo1SrjPgVPer1tGUHJlh69O+CS6IapcQY+uTp5cWtCBmr" fullword ascii /* score: '4.00'*/
      $s163 = "jb+L5INLh/hkz9GvZudvYjTG5+aanL8hogHJ4GdEE/LbL3VNfJ0EXxf7u0kUtQO1" fullword ascii /* score: '4.00'*/
      $s164 = "lN/\\znVtKq| " fullword ascii /* score: '4.00'*/
      $s165 = "RhqH]p_" fullword ascii /* score: '4.00'*/
      $s166 = "C_.ufW" fullword ascii /* score: '4.00'*/
      $s167 = "aWduTVBLSS0yLTM5NTAdBgNVHQ4EFgQUEP9+c0DI0C+O1m+1MiEUQCdulcQwHwYD" fullword ascii /* score: '4.00'*/
      $s168 = "My3L0bhloc+2CHFK4b2ONREPCcyuOpXmoBdS1L/YkG7eA0op49wlmQNc1YSC6jsc" fullword ascii /* score: '4.00'*/
      $s169 = ",hPxH0T[" fullword ascii /* score: '4.00'*/
      $s170 = "^wqziTWy" fullword ascii /* score: '4.00'*/
      $s171 = "RTmj%-RPZ" fullword ascii /* score: '4.00'*/
      $s172 = "M62oegXwVzkafiWb3bVt34bjIQc4vbBa2acXxsoa2+hK" fullword ascii /* score: '4.00'*/
      $s173 = "ASShB_[" fullword ascii /* score: '4.00'*/
      $s174 = "nQRfF/u7SRS1A7XGm/i/FgSfPqXb2dUGJjJhAGv+8YuXREPurs13rIKuUQOPXhEb" fullword ascii /* score: '4.00'*/
      $s175 = "hBRK\"a" fullword ascii /* score: '4.00'*/
      $s176 = "PUDo'7S" fullword ascii /* score: '4.00'*/
      $s177 = "kecqVRlxonAqPUFZ3C6P7kSXN7CvJKxAu/TfEnBaKmMG1a6jK+E3zZJ2zVbGfv8H" fullword ascii /* score: '4.00'*/
      $s178 = "rWrlKHc" fullword ascii /* score: '4.00'*/
      $s179 = "rPbRu0HY" fullword ascii /* score: '4.00'*/
      $s180 = "2AtLE!" fullword ascii /* score: '4.00'*/
      $s181 = "FVLs>Aw" fullword ascii /* score: '4.00'*/
      $s182 = "dMWEj_H" fullword ascii /* score: '4.00'*/
      $s183 = "S15wj7h7tKE8tHPtAJOVUw93NOW1ntWaeJ7an+cyZTiN4cXAlxviS0/qU4qgDO7Q" fullword ascii /* score: '4.00'*/
      $s184 = "OGZkMDhlZDUyNTZmMzYzMy9MYXRlc3RDUkwuY3JsMDcGCCsGAQUFBwEBBCswKTAn" fullword ascii /* score: '4.00'*/
      $s185 = "zy7HIVCv5Rsd1pMkBhaDFcdQzPDtg37EnEvXLXM4u9oEUtQj2OKVY6i2jHsiKdb2" fullword ascii /* score: '4.00'*/
      $s186 = "DIMkd~6" fullword ascii /* score: '4.00'*/
      $s187 = "7RFQK!" fullword ascii /* score: '4.00'*/
      $s188 = "mUBR]t r]" fullword ascii /* score: '4.00'*/
      $s189 = "VR0jBBgwFoAUuXvP66VCBkRfpULk4vT3jiK0zk8wDQYJKoZIhvcNAQELBQADggIB" fullword ascii /* score: '4.00'*/
      $s190 = "/s0ei3DxQp61AJai" fullword ascii /* score: '4.00'*/
      $s191 = "_L@XTaP,Wq" fullword ascii /* score: '4.00'*/
      $s192 = "KxAxXgty! " fullword ascii /* score: '4.00'*/
      $s193 = "vToi@SI" fullword ascii /* score: '4.00'*/
      $s194 = "WZkf]T57" fullword ascii /* score: '4.00'*/
      $s195 = "AfZ7zBzPlIkDYX0CXjA7z++s9p6N6UEf9IR5fH7hvrtDiigRWxEs8+neykBUXM8V" fullword ascii /* score: '4.00'*/
      $s196 = "WqKIwyg" fullword ascii /* score: '4.00'*/
      $s197 = "hnUHR!" fullword ascii /* score: '4.00'*/
      $s198 = "DgngNc8SOvOpCJmfIocX47tTe1x1PisJOSDLbHHV16Ch8A16ia74bwIDAQABo4IB" fullword ascii /* score: '4.00'*/
      $s199 = "dWlT\\(" fullword ascii /* score: '4.00'*/
      $s200 = "UTMvc8Jm61ULVNcuz55d1cfeodPgrHK6Dldfn/nFs0PgcVpDUx/CutRA50cOnFSA" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule ea3b2c23df3162a6fa5c9d22d03f50db30542d7570ef769ded4ef106fb0255f4 {
   meta:
      description = "Amadey_MALW - file ea3b2c23df3162a6fa5c9d22d03f50db30542d7570ef769ded4ef106fb0255f4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "ea3b2c23df3162a6fa5c9d22d03f50db30542d7570ef769ded4ef106fb0255f4"
   strings:
      $s1 = "UqpB- s" fullword ascii /* score: '8.00'*/
      $s2 = "ciiwgwvg" fullword ascii /* score: '8.00'*/
      $s3 = "blyxsede" fullword ascii /* score: '8.00'*/
      $s4 = "=<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s5 = "(&cMd'E" fullword ascii /* score: '6.00'*/
      $s6 = "+XX /d" fullword ascii /* score: '5.00'*/
      $s7 = "`1-;+  " fullword ascii /* score: '5.00'*/
      $s8 = "(+ >=)" fullword ascii /* score: '5.00'*/
      $s9 = "0{r\"+ " fullword ascii /* score: '5.00'*/
      $s10 = "q%- 87" fullword ascii /* score: '5.00'*/
      $s11 = "% n) h- P4" fullword ascii /* score: '5.00'*/
      $s12 = "`+ NPz" fullword ascii /* score: '5.00'*/
      $s13 = "D- |nR" fullword ascii /* score: '5.00'*/
      $s14 = ">- \\\\RwQ" fullword ascii /* score: '5.00'*/
      $s15 = ". -wXwS" fullword ascii /* score: '5.00'*/
      $s16 = "DmwmBk0" fullword ascii /* score: '5.00'*/
      $s17 = "( c- Z1 " fullword ascii /* score: '5.00'*/
      $s18 = "m.C{- _S" fullword ascii /* score: '5.00'*/
      $s19 = "^>zLM* " fullword ascii /* score: '5.00'*/
      $s20 = "l\"=pDV  -OI" fullword ascii /* score: '5.00'*/
      $s21 = "6- 99/" fullword ascii /* score: '5.00'*/
      $s22 = "lUuk)`~" fullword ascii /* score: '4.00'*/
      $s23 = "y.YQwRTK;\\" fullword ascii /* score: '4.00'*/
      $s24 = "JibKg\"" fullword ascii /* score: '4.00'*/
      $s25 = "LQGE+$V" fullword ascii /* score: '4.00'*/
      $s26 = "DptdL@O" fullword ascii /* score: '4.00'*/
      $s27 = "pKPZH[ j" fullword ascii /* score: '4.00'*/
      $s28 = "cUNo)\\!%8+" fullword ascii /* score: '4.00'*/
      $s29 = "CQSY[@~" fullword ascii /* score: '4.00'*/
      $s30 = "SYcw2_`" fullword ascii /* score: '4.00'*/
      $s31 = "isjjXAY" fullword ascii /* score: '4.00'*/
      $s32 = "ZZYB&H;%" fullword ascii /* score: '4.00'*/
      $s33 = "6% D`)bCHKX^A" fullword ascii /* score: '4.00'*/
      $s34 = "fu,KYPKFD&8" fullword ascii /* score: '4.00'*/
      $s35 = "qHJH'U:" fullword ascii /* score: '4.00'*/
      $s36 = "WYhLSf/1" fullword ascii /* score: '4.00'*/
      $s37 = "TRkvx%|" fullword ascii /* score: '4.00'*/
      $s38 = "TnCVE$'PQ" fullword ascii /* score: '4.00'*/
      $s39 = "rLuy.0c" fullword ascii /* score: '4.00'*/
      $s40 = "YAsw[;iI" fullword ascii /* score: '4.00'*/
      $s41 = "WdyL@4l+Y" fullword ascii /* score: '4.00'*/
      $s42 = ")CnEt?" fullword ascii /* score: '4.00'*/
      $s43 = "BmYGIt(b" fullword ascii /* score: '4.00'*/
      $s44 = "vVXu?g" fullword ascii /* score: '4.00'*/
      $s45 = "ZXRSm[ " fullword ascii /* score: '4.00'*/
      $s46 = "ZXBt\\3W" fullword ascii /* score: '4.00'*/
      $s47 = "wJskXu^" fullword ascii /* score: '4.00'*/
      $s48 = "prqMw.%" fullword ascii /* score: '4.00'*/
      $s49 = "RWIo@*0b" fullword ascii /* score: '4.00'*/
      $s50 = "vivWs9I" fullword ascii /* score: '4.00'*/
      $s51 = "ception sIvf" fullword ascii /* score: '4.00'*/
      $s52 = "ccTLL,T" fullword ascii /* score: '4.00'*/
      $s53 = "rnty*\\" fullword ascii /* score: '4.00'*/
      $s54 = "!kxiu?" fullword ascii /* score: '4.00'*/
      $s55 = "PDOBJ-=" fullword ascii /* score: '4.00'*/
      $s56 = ";sptjRKv" fullword ascii /* score: '4.00'*/
      $s57 = "[RqTEsdZ" fullword ascii /* score: '4.00'*/
      $s58 = "BxOi0(e" fullword ascii /* score: '4.00'*/
      $s59 = "QIOMe?" fullword ascii /* score: '4.00'*/
      $s60 = "AgxAkFp?H@" fullword ascii /* score: '4.00'*/
      $s61 = "dsIT9Hr@" fullword ascii /* score: '4.00'*/
      $s62 = "kidv7h(W" fullword ascii /* score: '4.00'*/
      $s63 = "2bWyrMF*" fullword ascii /* score: '4.00'*/
      $s64 = "_|HRuITq/" fullword ascii /* score: '4.00'*/
      $s65 = "kDMiYaq" fullword ascii /* score: '4.00'*/
      $s66 = "cekLYVJ{*" fullword ascii /* score: '4.00'*/
      $s67 = "yVzqQ\"@" fullword ascii /* score: '4.00'*/
      $s68 = "pJSJ?/&" fullword ascii /* score: '4.00'*/
      $s69 = "BxuQ!I" fullword ascii /* score: '4.00'*/
      $s70 = ",W;eIng!" fullword ascii /* score: '4.00'*/
      $s71 = "2ITfB!2" fullword ascii /* score: '4.00'*/
      $s72 = "rSiuxYXX" fullword ascii /* score: '4.00'*/
      $s73 = "QjiwLVK" fullword ascii /* score: '4.00'*/
      $s74 = "~vRwv`#E-fD\"" fullword ascii /* score: '4.00'*/
      $s75 = "UTwP!;-" fullword ascii /* score: '4.00'*/
      $s76 = "ZW#|czFa\\Q" fullword ascii /* score: '4.00'*/
      $s77 = "tONumZ)" fullword ascii /* score: '4.00'*/
      $s78 = "rthR}T5e8" fullword ascii /* score: '4.00'*/
      $s79 = "lsjjk@Y" fullword ascii /* score: '4.00'*/
      $s80 = "WtEQ!p4" fullword ascii /* score: '4.00'*/
      $s81 = "FOJy@?{" fullword ascii /* score: '4.00'*/
      $s82 = "kpMH%`," fullword ascii /* score: '4.00'*/
      $s83 = "ARbCIB=^" fullword ascii /* score: '4.00'*/
      $s84 = "{nuvf1=b" fullword ascii /* score: '4.00'*/
      $s85 = "KJQVrPQP" fullword ascii /* score: '4.00'*/
      $s86 = ";GoFCxb<" fullword ascii /* score: '4.00'*/
      $s87 = "^KNXm-1P" fullword ascii /* score: '4.00'*/
      $s88 = "qZWsx/^" fullword ascii /* score: '4.00'*/
      $s89 = "!hjVQq^%" fullword ascii /* score: '4.00'*/
      $s90 = "@xYXShZ)T" fullword ascii /* score: '4.00'*/
      $s91 = "YUShb\"" fullword ascii /* score: '4.00'*/
      $s92 = "6maoCHkc@\"" fullword ascii /* score: '4.00'*/
      $s93 = ")2S4BXRqxzU" fullword ascii /* score: '4.00'*/
      $s94 = ".Weu%9)" fullword ascii /* score: '4.00'*/
      $s95 = "zXLg[?|" fullword ascii /* score: '4.00'*/
      $s96 = "kWrtfh2Q(" fullword ascii /* score: '4.00'*/
      $s97 = "GyoKN0)" fullword ascii /* score: '4.00'*/
      $s98 = "yQbC+7MBs" fullword ascii /* score: '4.00'*/
      $s99 = "|Q.TYG" fullword ascii /* score: '4.00'*/
      $s100 = "TItirWy" fullword ascii /* score: '4.00'*/
      $s101 = "yZkTT!" fullword ascii /* score: '4.00'*/
      $s102 = "Z@)XXxfR1~~O" fullword ascii /* score: '4.00'*/
      $s103 = ".Azd!S" fullword ascii /* score: '4.00'*/
      $s104 = "){5JKXHIXL" fullword ascii /* score: '4.00'*/
      $s105 = ">RBmLWUl" fullword ascii /* score: '4.00'*/
      $s106 = "Aiyr\\dv" fullword ascii /* score: '4.00'*/
      $s107 = "ytADp]\"" fullword ascii /* score: '4.00'*/
      $s108 = "XWhC2_s" fullword ascii /* score: '4.00'*/
      $s109 = "IkWG]&\"9$" fullword ascii /* score: '4.00'*/
      $s110 = "FWeM%S:" fullword ascii /* score: '4.00'*/
      $s111 = "ykCN)' " fullword ascii /* score: '4.00'*/
      $s112 = "1=@%s~.}" fullword ascii /* score: '4.00'*/
      $s113 = "wSmI2O}L" fullword ascii /* score: '4.00'*/
      $s114 = "deIF\\P" fullword ascii /* score: '4.00'*/
      $s115 = "qCWV-r_@" fullword ascii /* score: '4.00'*/
      $s116 = "@TbcPHQL" fullword ascii /* score: '4.00'*/
      $s117 = "JWoLKo^3," fullword ascii /* score: '4.00'*/
      $s118 = "XAATQ\"" fullword ascii /* score: '4.00'*/
      $s119 = "AIpBa 8" fullword ascii /* score: '4.00'*/
      $s120 = "X5joShaMF" fullword ascii /* score: '4.00'*/
      $s121 = "TSILFZ%3" fullword ascii /* score: '4.00'*/
      $s122 = "HQls$hP" fullword ascii /* score: '4.00'*/
      $s123 = "fYwi|4-" fullword ascii /* score: '4.00'*/
      $s124 = "W,\\UKDf6\"*" fullword ascii /* score: '4.00'*/
      $s125 = "VaHELa}M" fullword ascii /* score: '4.00'*/
      $s126 = "adaZ!&" fullword ascii /* score: '4.00'*/
      $s127 = "IosyQIt" fullword ascii /* score: '4.00'*/
      $s128 = "Ufai00WyZi" fullword ascii /* score: '4.00'*/
      $s129 = " WRMD.1^" fullword ascii /* score: '4.00'*/
      $s130 = "gnpJ0F4{iI@" fullword ascii /* score: '4.00'*/
      $s131 = "ZCsMhK`" fullword ascii /* score: '4.00'*/
      $s132 = "RuN}bf$" fullword ascii /* score: '4.00'*/
      $s133 = "bqGIf#P2" fullword ascii /* score: '4.00'*/
      $s134 = "*ZpPbKTx" fullword ascii /* score: '4.00'*/
      $s135 = "YCFa2@p`" fullword ascii /* score: '4.00'*/
      $s136 = "sOju@O@l!#T" fullword ascii /* score: '4.00'*/
      $s137 = "YMZJz!" fullword ascii /* score: '4.00'*/
      $s138 = "fEhV@THt" fullword ascii /* score: '4.00'*/
      $s139 = "eAiF;y+" fullword ascii /* score: '4.00'*/
      $s140 = "<lakq!)" fullword ascii /* score: '4.00'*/
      $s141 = "jMKe^mN" fullword ascii /* score: '4.00'*/
      $s142 = "v%%d^^k" fullword ascii /* score: '4.00'*/
      $s143 = "C6iTTu[Ny" fullword ascii /* score: '4.00'*/
      $s144 = "lWhB3_`" fullword ascii /* score: '4.00'*/
      $s145 = "BYjIHyp`" fullword ascii /* score: '4.00'*/
      $s146 = "gOkeU='" fullword ascii /* score: '4.00'*/
      $s147 = "qUiV>c1" fullword ascii /* score: '4.00'*/
      $s148 = "1HXNv4%K" fullword ascii /* score: '4.00'*/
      $s149 = "xZqh%Wj" fullword ascii /* score: '4.00'*/
      $s150 = "LJGRZLdr" fullword ascii /* score: '4.00'*/
      $s151 = "YZrIZL~" fullword ascii /* score: '4.00'*/
      $s152 = "!hrtXxSh" fullword ascii /* score: '4.00'*/
      $s153 = "MrOL _Qa|LiF" fullword ascii /* score: '4.00'*/
      $s154 = "iqHMY%F" fullword ascii /* score: '4.00'*/
      $s155 = "+J%a;Q" fullword ascii /* score: '3.50'*/
      $s156 = "KNOTTX" fullword ascii /* score: '3.50'*/
      $s157 = "#\"DP3 %f:X$" fullword ascii /* score: '3.50'*/
      $s158 = "KXQTKY" fullword ascii /* score: '3.50'*/
      $s159 = " fwiud" fullword ascii /* score: '3.00'*/
      $s160 = "xa:\"Tb:3V^" fullword ascii /* score: '3.00'*/
      $s161 = "\\b@xU*D\\" fullword ascii /* score: '2.00'*/
      $s162 = "\\ZR`tb" fullword ascii /* score: '2.00'*/
      $s163 = "\\-ke !" fullword ascii /* score: '2.00'*/
      $s164 = "\\6@hj%" fullword ascii /* score: '2.00'*/
      $s165 = "\\43:Ge4" fullword ascii /* score: '2.00'*/
      $s166 = "\\0=-)Vn" fullword ascii /* score: '2.00'*/
      $s167 = "\\M$9`-" fullword ascii /* score: '2.00'*/
      $s168 = "\\RR`_81O" fullword ascii /* score: '2.00'*/
      $s169 = "\\].Y%T" fullword ascii /* score: '2.00'*/
      $s170 = "\\>R ZT`" fullword ascii /* score: '2.00'*/
      $s171 = "NvUU78" fullword ascii /* score: '2.00'*/
      $s172 = "GiXpL8" fullword ascii /* score: '2.00'*/
      $s173 = "\\s@2|E]" fullword ascii /* score: '2.00'*/
      $s174 = "\\c<NSa" fullword ascii /* score: '2.00'*/
      $s175 = "bkzgQ1" fullword ascii /* score: '2.00'*/
      $s176 = "\\l\\TSL" fullword ascii /* score: '2.00'*/
      $s177 = "\\V%(9n" fullword ascii /* score: '2.00'*/
      $s178 = "FltxG0" fullword ascii /* score: '2.00'*/
      $s179 = "\\s4`##" fullword ascii /* score: '2.00'*/
      $s180 = "\\$!82!gH4" fullword ascii /* score: '2.00'*/
      $s181 = "\\6RA ?([W" fullword ascii /* score: '2.00'*/
      $s182 = "VYhB39" fullword ascii /* score: '2.00'*/
      $s183 = "\\[So1T" fullword ascii /* score: '2.00'*/
      $s184 = "\\*|Gv%" fullword ascii /* score: '2.00'*/
      $s185 = "hQTJY3" fullword ascii /* score: '2.00'*/
      $s186 = "\\.!~$:b" fullword ascii /* score: '2.00'*/
      $s187 = "IwqtB3" fullword ascii /* score: '2.00'*/
      $s188 = "\\]\\DdU" fullword ascii /* score: '2.00'*/
      $s189 = "\\&%$mv" fullword ascii /* score: '2.00'*/
      $s190 = "\\QSzh`" fullword ascii /* score: '2.00'*/
      $s191 = "\\}R_v#B" fullword ascii /* score: '2.00'*/
      $s192 = "\\[RB]lM" fullword ascii /* score: '2.00'*/
      $s193 = "\\RZT/R" fullword ascii /* score: '2.00'*/
      $s194 = "\\&={<M" fullword ascii /* score: '2.00'*/
      $s195 = "\\xRe_<K" fullword ascii /* score: '2.00'*/
      $s196 = "\\2T:R]" fullword ascii /* score: '2.00'*/
      $s197 = "\\=Fw=~" fullword ascii /* score: '2.00'*/
      $s198 = "\\NbQnJr" fullword ascii /* score: '2.00'*/
      $s199 = "YUtX51" fullword ascii /* score: '2.00'*/
      $s200 = "\\1(PW/" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule sig_43e67fbb1bc6ac4549c216476b2aa4e98a89e74ce4d51b8d72380fdd8cc4edb1 {
   meta:
      description = "Amadey_MALW - file 43e67fbb1bc6ac4549c216476b2aa4e98a89e74ce4d51b8d72380fdd8cc4edb1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "43e67fbb1bc6ac4549c216476b2aa4e98a89e74ce4d51b8d72380fdd8cc4edb1"
   strings:
      $s1 = "ibpvakke" fullword ascii /* score: '8.00'*/
      $s2 = "dcmspmqj" fullword ascii /* score: '8.00'*/
      $s3 = "Un:\"+%7@" fullword ascii /* score: '7.00'*/
      $s4 = "1<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" fullword ascii /* score: '7.00'*/
      $s5 = "23+]Bq:\\" fullword ascii /* score: '7.00'*/
      $s6 = "/WqkOj%d-\\Pz" fullword ascii /* score: '6.50'*/
      $s7 = "s\\X|DLL" fullword ascii /* score: '6.00'*/
      $s8 = "iTEYe-" fullword ascii /* score: '6.00'*/
      $s9 = " (GeTs@" fullword ascii /* score: '6.00'*/
      $s10 = "V'- El-re" fullword ascii /* score: '5.00'*/
      $s11 = "_ /eA&" fullword ascii /* score: '5.00'*/
      $s12 = "fIuYdi2" fullword ascii /* score: '5.00'*/
      $s13 = "LRLkxHT8" fullword ascii /* score: '5.00'*/
      $s14 = "ZIh+ DQ" fullword ascii /* score: '5.00'*/
      $s15 = "$F%WeE%W" fullword ascii /* score: '5.00'*/
      $s16 = " ij/- 8" fullword ascii /* score: '5.00'*/
      $s17 = "v /Y4I" fullword ascii /* score: '5.00'*/
      $s18 = "%Do%+0" fullword ascii /* score: '5.00'*/
      $s19 = "aSmcl90" fullword ascii /* score: '5.00'*/
      $s20 = "VI(2!." fullword ascii /* score: '5.00'*/
      $s21 = "ZVXU619" fullword ascii /* score: '5.00'*/
      $s22 = "4- ~MZT" fullword ascii /* score: '5.00'*/
      $s23 = "IyDpE10" fullword ascii /* score: '5.00'*/
      $s24 = "<LR/ -" fullword ascii /* score: '5.00'*/
      $s25 = "ieTqpc8" fullword ascii /* score: '5.00'*/
      $s26 = "Rl+- 3" fullword ascii /* score: '5.00'*/
      $s27 = "]i(R -" fullword ascii /* score: '5.00'*/
      $s28 = "tE%EX%vO" fullword ascii /* score: '5.00'*/
      $s29 = "thixfr" fullword ascii /* score: '5.00'*/
      $s30 = "&ZHH- X#d" fullword ascii /* score: '5.00'*/
      $s31 = "Se1L+ ?F9" fullword ascii /* score: '5.00'*/
      $s32 = "]E /W3" fullword ascii /* score: '5.00'*/
      $s33 = "7|5\\+ " fullword ascii /* score: '5.00'*/
      $s34 = "\"b3)- " fullword ascii /* score: '5.00'*/
      $s35 = "UkxuI98" fullword ascii /* score: '5.00'*/
      $s36 = "KVYOuQ8" fullword ascii /* score: '5.00'*/
      $s37 = "\"@n- *" fullword ascii /* score: '5.00'*/
      $s38 = "#  T}`m" fullword ascii /* score: '5.00'*/
      $s39 = "&t%Sz%" fullword ascii /* score: '5.00'*/
      $s40 = "j-.kti" fullword ascii /* score: '4.00'*/
      $s41 = "G%VERWt?p1" fullword ascii /* score: '4.00'*/
      $s42 = "VDuEG o" fullword ascii /* score: '4.00'*/
      $s43 = "nQPS!|" fullword ascii /* score: '4.00'*/
      $s44 = "XDBIu,:" fullword ascii /* score: '4.00'*/
      $s45 = "UPSV)r{" fullword ascii /* score: '4.00'*/
      $s46 = "5SrIqq-:F" fullword ascii /* score: '4.00'*/
      $s47 = "ZuvXYP*" fullword ascii /* score: '4.00'*/
      $s48 = "idIcpHI" fullword ascii /* score: '4.00'*/
      $s49 = ">c.DLf" fullword ascii /* score: '4.00'*/
      $s50 = "utVQ)>k`" fullword ascii /* score: '4.00'*/
      $s51 = "HpdnLul" fullword ascii /* score: '4.00'*/
      $s52 = "LHPD!(" fullword ascii /* score: '4.00'*/
      $s53 = "I'yvbl+h1d" fullword ascii /* score: '4.00'*/
      $s54 = "VFSZSdA" fullword ascii /* score: '4.00'*/
      $s55 = "WVMa:98" fullword ascii /* score: '4.00'*/
      $s56 = "VLRB)^)" fullword ascii /* score: '4.00'*/
      $s57 = "lzpQ|dW" fullword ascii /* score: '4.00'*/
      $s58 = "jOlW'39" fullword ascii /* score: '4.00'*/
      $s59 = "QUeA<I6" fullword ascii /* score: '4.00'*/
      $s60 = "BKEf505C'" fullword ascii /* score: '4.00'*/
      $s61 = "h<TtTH?t{!" fullword ascii /* score: '4.00'*/
      $s62 = "yqOs`#5" fullword ascii /* score: '4.00'*/
      $s63 = "Ahxn@\"" fullword ascii /* score: '4.00'*/
      $s64 = "rHmA\\vqP\"l" fullword ascii /* score: '4.00'*/
      $s65 = "XzWQ:)." fullword ascii /* score: '4.00'*/
      $s66 = "MCsIYdq" fullword ascii /* score: '4.00'*/
      $s67 = "n/dlqL@\"" fullword ascii /* score: '4.00'*/
      $s68 = "vklTO^&z" fullword ascii /* score: '4.00'*/
      $s69 = "YNfsZ0T" fullword ascii /* score: '4.00'*/
      $s70 = ".jqw]\\" fullword ascii /* score: '4.00'*/
      $s71 = "nZARVhp" fullword ascii /* score: '4.00'*/
      $s72 = "NjrP3Bh" fullword ascii /* score: '4.00'*/
      $s73 = "ThZwF~\"" fullword ascii /* score: '4.00'*/
      $s74 = "<k|jyQD)$ " fullword ascii /* score: '4.00'*/
      $s75 = "/WUghDga" fullword ascii /* score: '4.00'*/
      $s76 = "tuLST3X" fullword ascii /* score: '4.00'*/
      $s77 = "bdSwN7J[ " fullword ascii /* score: '4.00'*/
      $s78 = "gErp ,@" fullword ascii /* score: '4.00'*/
      $s79 = "iwfuy?M" fullword ascii /* score: '4.00'*/
      $s80 = "\"VTUSp?-f" fullword ascii /* score: '4.00'*/
      $s81 = "AdGj\"D" fullword ascii /* score: '4.00'*/
      $s82 = "wGtk|Oxct" fullword ascii /* score: '4.00'*/
      $s83 = "|k.viy" fullword ascii /* score: '4.00'*/
      $s84 = "PTxJ\"_" fullword ascii /* score: '4.00'*/
      $s85 = " M8.efR*" fullword ascii /* score: '4.00'*/
      $s86 = "zZuse<vN" fullword ascii /* score: '4.00'*/
      $s87 = "atSs\\," fullword ascii /* score: '4.00'*/
      $s88 = "uKmT'\"" fullword ascii /* score: '4.00'*/
      $s89 = "JWAA,:X," fullword ascii /* score: '4.00'*/
      $s90 = "BDOA0cRm9lp" fullword ascii /* score: '4.00'*/
      $s91 = "ljDi|;tTt" fullword ascii /* score: '4.00'*/
      $s92 = "pZtZEJ!" fullword ascii /* score: '4.00'*/
      $s93 = "LdGf_,*" fullword ascii /* score: '4.00'*/
      $s94 = "\"SiBR\\FR" fullword ascii /* score: '4.00'*/
      $s95 = ":eavU?" fullword ascii /* score: '4.00'*/
      $s96 = "jszE,;B>" fullword ascii /* score: '4.00'*/
      $s97 = "h1WQXR3g[" fullword ascii /* score: '4.00'*/
      $s98 = "TOxh}\\ " fullword ascii /* score: '4.00'*/
      $s99 = "|(%D?<" fullword ascii /* score: '4.00'*/
      $s100 = "MrEGVbN" fullword ascii /* score: '4.00'*/
      $s101 = "@gsTI@=;" fullword ascii /* score: '4.00'*/
      $s102 = "PQkIyb'}M0" fullword ascii /* score: '4.00'*/
      $s103 = "qaAf)>!*" fullword ascii /* score: '4.00'*/
      $s104 = "tIJAM\\" fullword ascii /* score: '4.00'*/
      $s105 = "$VNZsv%]" fullword ascii /* score: '4.00'*/
      $s106 = "YxKf@C^'" fullword ascii /* score: '4.00'*/
      $s107 = "vqLp_)z;" fullword ascii /* score: '4.00'*/
      $s108 = "iWsVm8j)[:" fullword ascii /* score: '4.00'*/
      $s109 = "ktle%D2" fullword ascii /* score: '4.00'*/
      $s110 = "$$72.Piu" fullword ascii /* score: '4.00'*/
      $s111 = "BrPTXw^" fullword ascii /* score: '4.00'*/
      $s112 = " X`%D#" fullword ascii /* score: '4.00'*/
      $s113 = "HAWWU\")" fullword ascii /* score: '4.00'*/
      $s114 = "OiYDPdq@" fullword ascii /* score: '4.00'*/
      $s115 = "SN.JVY$" fullword ascii /* score: '4.00'*/
      $s116 = ",y`Xpckgh8" fullword ascii /* score: '4.00'*/
      $s117 = "thiuDdN" fullword ascii /* score: '4.00'*/
      $s118 = "LlBrq3h0" fullword ascii /* score: '4.00'*/
      $s119 = "lYAJ--L" fullword ascii /* score: '4.00'*/
      $s120 = "ocxa9eHu[p(^PTR#" fullword ascii /* score: '4.00'*/
      $s121 = "yrus&']N" fullword ascii /* score: '4.00'*/
      $s122 = "HAJbweE" fullword ascii /* score: '4.00'*/
      $s123 = "q_NJKl( f%)>|" fullword ascii /* score: '4.00'*/
      $s124 = "haWr6NY" fullword ascii /* score: '4.00'*/
      $s125 = "KdwIH8y" fullword ascii /* score: '4.00'*/
      $s126 = "nRUb}u\\cTB" fullword ascii /* score: '4.00'*/
      $s127 = "`RDHEoy4)" fullword ascii /* score: '4.00'*/
      $s128 = "sotTE3[$" fullword ascii /* score: '4.00'*/
      $s129 = "qDIwe='" fullword ascii /* score: '4.00'*/
      $s130 = "RpiP5AZ" fullword ascii /* score: '4.00'*/
      $s131 = "ywthQfz" fullword ascii /* score: '4.00'*/
      $s132 = "i(YtbpXDo" fullword ascii /* score: '4.00'*/
      $s133 = "dFlL<0Z" fullword ascii /* score: '4.00'*/
      $s134 = "BRCe\"{" fullword ascii /* score: '4.00'*/
      $s135 = ".jidm\\F" fullword ascii /* score: '4.00'*/
      $s136 = "wbzX Z`x" fullword ascii /* score: '4.00'*/
      $s137 = "NRBdq,I" fullword ascii /* score: '4.00'*/
      $s138 = "JgPLl2%" fullword ascii /* score: '4.00'*/
      $s139 = "XhgLTv/" fullword ascii /* score: '4.00'*/
      $s140 = "exwNXu_" fullword ascii /* score: '4.00'*/
      $s141 = "bwjN ,'Q" fullword ascii /* score: '4.00'*/
      $s142 = "-@.bDW" fullword ascii /* score: '4.00'*/
      $s143 = "`,LakQ!" fullword ascii /* score: '4.00'*/
      $s144 = "seJC'}el" fullword ascii /* score: '4.00'*/
      $s145 = "LjrLSA7_" fullword ascii /* score: '4.00'*/
      $s146 = "fmJXwSw" fullword ascii /* score: '4.00'*/
      $s147 = "dRMULOK" fullword ascii /* score: '4.00'*/
      $s148 = "luIP;<." fullword ascii /* score: '4.00'*/
      $s149 = "IsWZ_P$" fullword ascii /* score: '4.00'*/
      $s150 = "kqrK2yT" fullword ascii /* score: '4.00'*/
      $s151 = "KtMXPd!" fullword ascii /* score: '4.00'*/
      $s152 = "%^%b-$" fullword ascii /* score: '3.50'*/
      $s153 = "y%q-?0" fullword ascii /* score: '3.50'*/
      $s154 = "Jzfppk" fullword ascii /* score: '3.00'*/
      $s155 = "QtgGK1" fullword ascii /* score: '2.00'*/
      $s156 = "\\'29 `5" fullword ascii /* score: '2.00'*/
      $s157 = "\\POffE" fullword ascii /* score: '2.00'*/
      $s158 = "\\:)C.b{" fullword ascii /* score: '2.00'*/
      $s159 = "\\6!1Ks" fullword ascii /* score: '2.00'*/
      $s160 = "\\IUnE[" fullword ascii /* score: '2.00'*/
      $s161 = "uaySY0" fullword ascii /* score: '2.00'*/
      $s162 = "aHiJt5" fullword ascii /* score: '2.00'*/
      $s163 = "\\uY$]4" fullword ascii /* score: '2.00'*/
      $s164 = "\\~$'2\\" fullword ascii /* score: '2.00'*/
      $s165 = "\\\\O8*e" fullword ascii /* score: '2.00'*/
      $s166 = "\\m4hv-" fullword ascii /* score: '2.00'*/
      $s167 = "\\_eOa(" fullword ascii /* score: '2.00'*/
      $s168 = "TYRPG7" fullword ascii /* score: '2.00'*/
      $s169 = "\\^})-Yn" fullword ascii /* score: '2.00'*/
      $s170 = "tDTEW2" fullword ascii /* score: '2.00'*/
      $s171 = "ptYp71" fullword ascii /* score: '2.00'*/
      $s172 = "\\XPAe'" fullword ascii /* score: '2.00'*/
      $s173 = "auzdE8" fullword ascii /* score: '2.00'*/
      $s174 = "\\&-et-" fullword ascii /* score: '2.00'*/
      $s175 = "\\(dCLS" fullword ascii /* score: '2.00'*/
      $s176 = "\\>qWT5" fullword ascii /* score: '2.00'*/
      $s177 = "mOWQh9" fullword ascii /* score: '2.00'*/
      $s178 = "\\.R$Hk&z A" fullword ascii /* score: '2.00'*/
      $s179 = "\\v`2>L" fullword ascii /* score: '2.00'*/
      $s180 = "\\rTa'1" fullword ascii /* score: '2.00'*/
      $s181 = "kuFZK4" fullword ascii /* score: '2.00'*/
      $s182 = "\\| a0x" fullword ascii /* score: '2.00'*/
      $s183 = "\\kpV/L0" fullword ascii /* score: '2.00'*/
      $s184 = "\\XYH~M" fullword ascii /* score: '2.00'*/
      $s185 = "\\O'|1zU2" fullword ascii /* score: '2.00'*/
      $s186 = "\\ kWFq" fullword ascii /* score: '2.00'*/
      $s187 = "\\H>e(5" fullword ascii /* score: '2.00'*/
      $s188 = "\\!k`^1" fullword ascii /* score: '2.00'*/
      $s189 = "\\E@931" fullword ascii /* score: '2.00'*/
      $s190 = "\\cm1k=" fullword ascii /* score: '2.00'*/
      $s191 = "\\fM3H;" fullword ascii /* score: '2.00'*/
      $s192 = "wioAr8" fullword ascii /* score: '2.00'*/
      $s193 = "\\EXf1Z" fullword ascii /* score: '2.00'*/
      $s194 = "IpJNs0" fullword ascii /* score: '2.00'*/
      $s195 = "\\'6 `B%" fullword ascii /* score: '2.00'*/
      $s196 = "\\rR0xXJ" fullword ascii /* score: '2.00'*/
      $s197 = "\\/i,Np" fullword ascii /* score: '2.00'*/
      $s198 = "\\h<$q,Yv " fullword ascii /* score: '2.00'*/
      $s199 = "_^][ZYX" fullword ascii /* score: '1.00'*/
      $s200 = "_^][ZY" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule sig_4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf {
   meta:
      description = "Amadey_MALW - file 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
   strings:
      $s1 = "xAVdL87.exe" fullword ascii /* score: '22.00'*/
      $s2 = "y99pO20.exe" fullword ascii /* score: '19.00'*/
      $s3 = "za040112.exe" fullword ascii /* score: '19.00'*/
      $s4 = "v3214Hv.exe" fullword ascii /* score: '19.00'*/
      $s5 = "tz4603.exe" fullword ascii /* score: '19.00'*/
      $s6 = "333333333333333347" ascii /* score: '17.00'*/ /* hex encoded string '33333333G' */
      $s7 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s8 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s9 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s10 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s11 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s12 = "* 6:Qos" fullword ascii /* score: '9.00'*/
      $s13 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s14 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s15 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii /* score: '7.00'*/
      $s16 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii /* score: '7.00'*/
      $s17 = "p:\\SOb*" fullword ascii /* score: '7.00'*/
      $s18 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii /* score: '7.00'*/
      $s19 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s20 = "PAPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s21 = "TUUUUUUPU" fullword ascii /* score: '6.50'*/
      $s22 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s23 = "a%-**<y9\"m(* " fullword ascii /* score: '5.00'*/
      $s24 = "wHDKfC0" fullword ascii /* score: '5.00'*/
      $s25 = "^ -fJ:n" fullword ascii /* score: '5.00'*/
      $s26 = "J}Kq%s%" fullword ascii /* score: '5.00'*/
      $s27 = "C%I%/`" fullword ascii /* score: '5.00'*/
      $s28 = "T -?:_" fullword ascii /* score: '5.00'*/
      $s29 = "hLlspH9" fullword ascii /* score: '5.00'*/
      $s30 = "RSDSwb6" fullword ascii /* score: '5.00'*/
      $s31 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s32 = "Extracting" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 13 times */
      $s33 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s34 = "Extract" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 42 times */
      $s35 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s36 = "PendingFileRenameOperations" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 52 times */
      $s37 = "RegServer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.94'*/ /* Goodware String - occured 57 times */
      $s38 = "Reboot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 105 times */
      $s39 = "SeShutdownPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s40 = "Internet Explorer" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s41 = "-tXABn-xr" fullword ascii /* score: '4.00'*/
      $s42 = "P?IanI2v6" fullword ascii /* score: '4.00'*/
      $s43 = "KNWT% %W" fullword ascii /* score: '4.00'*/
      $s44 = "hvyZ2U` " fullword ascii /* score: '4.00'*/
      $s45 = "yQIwx_D" fullword ascii /* score: '4.00'*/
      $s46 = "=\">>>G>R>Y>p>v>|>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s47 = "tNuGY*W" fullword ascii /* score: '4.00'*/
      $s48 = "7Egwt?fRq" fullword ascii /* score: '4.00'*/
      $s49 = "OsssXwuy_P" fullword ascii /* score: '4.00'*/
      $s50 = "7BOnQ?Y" fullword ascii /* score: '4.00'*/
      $s51 = "-sZHf@g\\" fullword ascii /* score: '4.00'*/
      $s52 = "dUVxVUw" fullword ascii /* score: '4.00'*/
      $s53 = "rMEPvw{" fullword ascii /* score: '4.00'*/
      $s54 = "SBfxqN." fullword ascii /* score: '4.00'*/
      $s55 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s56 = "HW&.FSO" fullword ascii /* score: '4.00'*/
      $s57 = "qZlGA,[" fullword ascii /* score: '4.00'*/
      $s58 = "XVGb&T_" fullword ascii /* score: '4.00'*/
      $s59 = "yeBlOr(D" fullword ascii /* score: '4.00'*/
      $s60 = "PGuB($G" fullword ascii /* score: '4.00'*/
      $s61 = "jYVp!G:" fullword ascii /* score: '4.00'*/
      $s62 = "phOH`LL" fullword ascii /* score: '4.00'*/
      $s63 = "(0qUrzpae[." fullword ascii /* score: '4.00'*/
      $s64 = "mJljk]r" fullword ascii /* score: '4.00'*/
      $s65 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s66 = "(%LVHP5=(" fullword ascii /* score: '4.00'*/
      $s67 = "?+?1?<?B?N?^?g?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s68 = "erwF)M+" fullword ascii /* score: '4.00'*/
      $s69 = "egFO$QQ" fullword ascii /* score: '4.00'*/
      $s70 = "mMiTDVu" fullword ascii /* score: '4.00'*/
      $s71 = "=X)B+FShyP3s" fullword ascii /* score: '4.00'*/
      $s72 = "bein)i/*" fullword ascii /* score: '4.00'*/
      $s73 = "9LTOGeG~" fullword ascii /* score: '4.00'*/
      $s74 = "mrWwfM@2{" fullword ascii /* score: '4.00'*/
      $s75 = "RjvU5yE" fullword ascii /* score: '4.00'*/
      $s76 = "xReh}gqB>" fullword ascii /* score: '4.00'*/
      $s77 = "P*I!&.Nsy$" fullword ascii /* score: '4.00'*/
      $s78 = "KuTBJa," fullword ascii /* score: '4.00'*/
      $s79 = "qxfKApWJR;" fullword ascii /* score: '4.00'*/
      $s80 = "5T)csKjHg:" fullword ascii /* score: '4.00'*/
      $s81 = "Zm.rBx" fullword ascii /* score: '4.00'*/
      $s82 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s83 = "pmqdX0~" fullword ascii /* score: '4.00'*/
      $s84 = "!:%S[w" fullword ascii /* score: '4.00'*/
      $s85 = "(oiPL\"I$" fullword ascii /* score: '4.00'*/
      $s86 = "Q+dZFk./N0" fullword ascii /* score: '4.00'*/
      $s87 = "_fekLcqldg" fullword ascii /* score: '4.00'*/
      $s88 = "U8}OkRssW9h" fullword ascii /* score: '4.00'*/
      $s89 = "shUJohs" fullword ascii /* score: '4.00'*/
      $s90 = "Fhrfa\"" fullword ascii /* score: '4.00'*/
      $s91 = "RyBL\"O" fullword ascii /* score: '4.00'*/
      $s92 = "qdlzTSA" fullword ascii /* score: '4.00'*/
      $s93 = "LQzBpBp" fullword ascii /* score: '4.00'*/
      $s94 = "WNHMP'B" fullword ascii /* score: '4.00'*/
      $s95 = "JApyCp4}" fullword ascii /* score: '4.00'*/
      $s96 = "uIegomR" fullword ascii /* score: '4.00'*/
      $s97 = "cRRp2ft" fullword ascii /* score: '4.00'*/
      $s98 = "9gGcj?" fullword ascii /* score: '4.00'*/
      $s99 = "oQOe7FM}l:*'" fullword ascii /* score: '4.00'*/
      $s100 = "bscf?B/lA" fullword ascii /* score: '4.00'*/
      $s101 = "IXse$=m" fullword ascii /* score: '4.00'*/
      $s102 = "QANL(6N" fullword ascii /* score: '4.00'*/
      $s103 = "vclEH,u!" fullword ascii /* score: '4.00'*/
      $s104 = "rdoVZn}" fullword ascii /* score: '4.00'*/
      $s105 = "_dcibko_" fullword ascii /* score: '4.00'*/
      $s106 = "jrzlz\\" fullword ascii /* score: '4.00'*/
      $s107 = "eEbW1Q9M" fullword ascii /* score: '4.00'*/
      $s108 = " Qe.hzs{" fullword ascii /* score: '4.00'*/
      $s109 = "dQSn3U)" fullword ascii /* score: '4.00'*/
      $s110 = "Iktz97J" fullword ascii /* score: '4.00'*/
      $s111 = "1'VqaH(y%" fullword ascii /* score: '4.00'*/
      $s112 = "?e?q?}?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s113 = "ZLvwP[R" fullword ascii /* score: '4.00'*/
      $s114 = "ecxE\"\"" fullword ascii /* score: '4.00'*/
      $s115 = "aUMJkAaw~u" fullword ascii /* score: '4.00'*/
      $s116 = "nEzm&J3" fullword ascii /* score: '4.00'*/
      $s117 = ":GcoN7O`" fullword ascii /* score: '4.00'*/
      $s118 = ".rdata$brc" fullword ascii /* score: '4.00'*/
      $s119 = "QtkIWhk" fullword ascii /* score: '4.00'*/
      $s120 = "3fScr@:'" fullword ascii /* score: '4.00'*/
      $s121 = "3FToCH b" fullword ascii /* score: '4.00'*/
      $s122 = "QdIN\"," fullword ascii /* score: '4.00'*/
      $s123 = "+VEeuD6,up0$6" fullword ascii /* score: '4.00'*/
      $s124 = "%>%D$LI" fullword ascii /* score: '4.00'*/
      $s125 = "XWstFfEW" fullword ascii /* score: '4.00'*/
      $s126 = "JBEb'u=" fullword ascii /* score: '4.00'*/
      $s127 = "ASal b`" fullword ascii /* score: '4.00'*/
      $s128 = "ySiHt,8h" fullword ascii /* score: '4.00'*/
      $s129 = "EhdGYV>" fullword ascii /* score: '4.00'*/
      $s130 = "HdDBm]#" fullword ascii /* score: '4.00'*/
      $s131 = "WWj WWWSW" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s132 = "hTwc\\1," fullword ascii /* score: '4.00'*/
      $s133 = "dmpnq{h" fullword ascii /* score: '4.00'*/
      $s134 = "JtFXviS" fullword ascii /* score: '4.00'*/
      $s135 = "AwTiM#;" fullword ascii /* score: '4.00'*/
      $s136 = "fPTdJ\"" fullword ascii /* score: '4.00'*/
      $s137 = "CIdwj,U@-7d" fullword ascii /* score: '4.00'*/
      $s138 = "XgBr0aa" fullword ascii /* score: '4.00'*/
      $s139 = "lLbO{v*" fullword ascii /* score: '4.00'*/
      $s140 = "n0CyOZm7[)Y" fullword ascii /* score: '4.00'*/
      $s141 = "mJev6TH" fullword ascii /* score: '4.00'*/
      $s142 = ";#;/;5;<;E;K;S;Y;f;n;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s143 = "NI(R.UdW" fullword ascii /* score: '4.00'*/
      $s144 = "xsO]OuOXO>;" fullword ascii /* score: '4.00'*/
      $s145 = "11.00.14393.0 (rs1_release.160715-1616)" fullword wide /* score: '4.00'*/
      $s146 = "WEXTRACT.EXE            .MUI" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s147 = "$L%e:O" fullword ascii /* score: '3.50'*/
      $s148 = "RCKSZE" fullword ascii /* score: '3.50'*/
      $s149 = "ODKXTY" fullword ascii /* score: '3.50'*/
      $s150 = "            <!--This Id value indicates the application supports Windows 7/Server 2008 R2 functionality-->" fullword ascii /* score: '3.00'*/
      $s151 = "D$HjDj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s152 = "00(0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s153 = ":<\\u6:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s154 = "SSh`2@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s155 = "33(313F3[3h3p3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s156 = "<At <Bt" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s157 = "            <!--This Id value indicates the application supports Windows 8/Server 2012 functionality-->" fullword ascii /* score: '3.00'*/
      $s158 = "          level=\"asInvoker\"" fullword ascii /* score: '3.00'*/
      $s159 = "bSSMC2" fullword ascii /* score: '2.00'*/
      $s160 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii /* score: '2.00'*/
      $s161 = "\\;l'O<Y" fullword ascii /* score: '2.00'*/
      $s162 = "\\~$@0d" fullword ascii /* score: '2.00'*/
      $s163 = "\\;IO'e" fullword ascii /* score: '2.00'*/
      $s164 = "\\X,mm2ks" fullword ascii /* score: '2.00'*/
      $s165 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " fullword ascii /* score: '2.00'*/
      $s166 = "gsqGi3" fullword ascii /* score: '2.00'*/
      $s167 = "TTSi55" fullword ascii /* score: '2.00'*/
      $s168 = "mjhAE6" fullword ascii /* score: '2.00'*/
      $s169 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s170 = "\\q T!Wzv" fullword ascii /* score: '2.00'*/
      $s171 = "\\DpQ-L_F" fullword ascii /* score: '2.00'*/
      $s172 = "fJNbc7" fullword ascii /* score: '2.00'*/
      $s173 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii /* score: '2.00'*/
      $s174 = "\\u}l)yl" fullword ascii /* score: '2.00'*/
      $s175 = "\\OH,DYh" fullword ascii /* score: '2.00'*/
      $s176 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii /* score: '2.00'*/
      $s177 = "\\ C3*o" fullword ascii /* score: '2.00'*/
      $s178 = "PA<None>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s179 = "VwKYM3" fullword ascii /* score: '2.00'*/
      $s180 = "\\K\"-0." fullword ascii /* score: '2.00'*/
      $s181 = "JtRtD8" fullword ascii /* score: '2.00'*/
      $s182 = "BmiIm0" fullword ascii /* score: '2.00'*/
      $s183 = "\\1EKI.]" fullword ascii /* score: '2.00'*/
      $s184 = "    </compatibility>" fullword ascii /* score: '2.00'*/
      $s185 = "\\`W7zk" fullword ascii /* score: '2.00'*/
      $s186 = "5D5S5c5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s187 = "\\$Q>AIwR1w" fullword ascii /* score: '2.00'*/
      $s188 = "\\3&B !B!" fullword ascii /* score: '2.00'*/
      $s189 = "\\cV7+{" fullword ascii /* score: '2.00'*/
      $s190 = "HhOfh8" fullword ascii /* score: '2.00'*/
      $s191 = "\\;n>f,d" fullword ascii /* score: '2.00'*/
      $s192 = "\\^`^!Y" fullword ascii /* score: '2.00'*/
      $s193 = "\\!?8_=;" fullword ascii /* score: '2.00'*/
      $s194 = "\\XR}`)" fullword ascii /* score: '2.00'*/
      $s195 = "fxkyx" fullword ascii /* score: '2.00'*/
      $s196 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s197 = ";~Gh29" fullword ascii /* score: '1.00'*/
      $s198 = "l6;gFf" fullword ascii /* score: '1.00'*/
      $s199 = "!K!3D%VbX" fullword ascii /* score: '1.00'*/
      $s200 = "~7Z>p]" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b {
   meta:
      description = "Amadey_MALW - file d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b"
   strings:
      $s1 = "xiSWl90.exe" fullword ascii /* score: '22.00'*/
      $s2 = "za408209.exe" fullword ascii /* score: '19.00'*/
      $s3 = "za193369.exe" fullword ascii /* score: '19.00'*/
      $s4 = "y85Rj40.exe" fullword ascii /* score: '19.00'*/
      $s5 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s6 = "Q1JqM28hb5" fullword ascii /* base64 encoded string 'CRj3o!o' */ /* score: '11.00'*/
      $s7 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s8 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s9 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s10 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s11 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s12 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s13 = "wORu /Wd" fullword ascii /* score: '8.00'*/
      $s14 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii /* score: '7.00'*/
      $s15 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii /* score: '7.00'*/
      $s16 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii /* score: '7.00'*/
      $s17 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s18 = "tmpJR7f" fullword ascii /* score: '7.00'*/
      $s19 = "yTt:\\)" fullword ascii /* score: '7.00'*/
      $s20 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s21 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s22 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s23 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s24 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s25 = "RSDSwb6" fullword ascii /* score: '5.00'*/
      $s26 = "{l4+ ~z" fullword ascii /* score: '5.00'*/
      $s27 = "MU|5?3 ->" fullword ascii /* score: '5.00'*/
      $s28 = "pzg* d" fullword ascii /* score: '5.00'*/
      $s29 = "+ B?~$@" fullword ascii /* score: '5.00'*/
      $s30 = "e{%w%w!w" fullword ascii /* score: '5.00'*/
      $s31 = "kF -ta" fullword ascii /* score: '5.00'*/
      $s32 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s33 = "Extracting" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 13 times */
      $s34 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s35 = "Extract" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 42 times */
      $s36 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s37 = "PendingFileRenameOperations" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 52 times */
      $s38 = "RegServer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.94'*/ /* Goodware String - occured 57 times */
      $s39 = "Reboot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 105 times */
      $s40 = "SeShutdownPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s41 = "Internet Explorer" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s42 = "P?IanI2v6" fullword ascii /* score: '4.00'*/
      $s43 = "hvyZ2U` " fullword ascii /* score: '4.00'*/
      $s44 = "=\">>>G>R>Y>p>v>|>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s45 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s46 = "jYVp!G:" fullword ascii /* score: '4.00'*/
      $s47 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s48 = "(%LVHP5=(" fullword ascii /* score: '4.00'*/
      $s49 = "?+?1?<?B?N?^?g?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s50 = "egFO$QQ" fullword ascii /* score: '4.00'*/
      $s51 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s52 = "!:%S[w" fullword ascii /* score: '4.00'*/
      $s53 = "eEbW1Q9M" fullword ascii /* score: '4.00'*/
      $s54 = "?e?q?}?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s55 = ".rdata$brc" fullword ascii /* score: '4.00'*/
      $s56 = "3fScr@:'" fullword ascii /* score: '4.00'*/
      $s57 = "ySiHt,8h" fullword ascii /* score: '4.00'*/
      $s58 = "WWj WWWSW" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s59 = "hTwc\\1," fullword ascii /* score: '4.00'*/
      $s60 = "lLbO{v*" fullword ascii /* score: '4.00'*/
      $s61 = ";#;/;5;<;E;K;S;Y;f;n;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s62 = "11.00.14393.0 (rs1_release.160715-1616)" fullword wide /* score: '4.00'*/
      $s63 = "WEXTRACT.EXE            .MUI" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s64 = "*PAEp}?;" fullword ascii /* score: '4.00'*/
      $s65 = "Ayfs6dT" fullword ascii /* score: '4.00'*/
      $s66 = "UArMQlk" fullword ascii /* score: '4.00'*/
      $s67 = "CIbwh*S>-7d" fullword ascii /* score: '4.00'*/
      $s68 = "OLNs[{r" fullword ascii /* score: '4.00'*/
      $s69 = "ieYBV3/" fullword ascii /* score: '4.00'*/
      $s70 = "lWHF6dh1" fullword ascii /* score: '4.00'*/
      $s71 = "nHEbNB39N" fullword ascii /* score: '4.00'*/
      $s72 = "WUCU5\"`Vf" fullword ascii /* score: '4.00'*/
      $s73 = "bEKpE#f+" fullword ascii /* score: '4.00'*/
      $s74 = "CHBT4cG" fullword ascii /* score: '4.00'*/
      $s75 = "BVVQ4W*" fullword ascii /* score: '4.00'*/
      $s76 = "4PePxc]O" fullword ascii /* score: '4.00'*/
      $s77 = "usrSgTk" fullword ascii /* score: '4.00'*/
      $s78 = "D`pttYrG^O4[" fullword ascii /* score: '4.00'*/
      $s79 = "AulyQ3u" fullword ascii /* score: '4.00'*/
      $s80 = "gctXs:GC" fullword ascii /* score: '4.00'*/
      $s81 = "KEMEy!" fullword ascii /* score: '4.00'*/
      $s82 = "isgq kb4" fullword ascii /* score: '4.00'*/
      $s83 = "fxPAr@RR" fullword ascii /* score: '4.00'*/
      $s84 = "BJExot0_" fullword ascii /* score: '4.00'*/
      $s85 = "piSBXqS." fullword ascii /* score: '4.00'*/
      $s86 = "iJlq6)\"" fullword ascii /* score: '4.00'*/
      $s87 = "gVlW)&S" fullword ascii /* score: '4.00'*/
      $s88 = "rbuG820|" fullword ascii /* score: '4.00'*/
      $s89 = "nOEcePDZ" fullword ascii /* score: '4.00'*/
      $s90 = "UUUUUUUUUUUUUUUUzT" fullword ascii /* score: '4.00'*/
      $s91 = "RIRF!|q" fullword ascii /* score: '4.00'*/
      $s92 = "^LLDK?" fullword ascii /* score: '4.00'*/
      $s93 = "81KXRiR~+/nbZ" fullword ascii /* score: '4.00'*/
      $s94 = "XaET?*" fullword ascii /* score: '4.00'*/
      $s95 = "WrZH9d+}" fullword ascii /* score: '4.00'*/
      $s96 = "ZV.sos" fullword ascii /* score: '4.00'*/
      $s97 = "Wlxm';6Lv" fullword ascii /* score: '4.00'*/
      $s98 = "NNfz/A+" fullword ascii /* score: '4.00'*/
      $s99 = "L+FVhf,-)" fullword ascii /* score: '4.00'*/
      $s100 = "nCrcD=q" fullword ascii /* score: '4.00'*/
      $s101 = "bEXCtdU" fullword ascii /* score: '4.00'*/
      $s102 = "(iKROiim'" fullword ascii /* score: '4.00'*/
      $s103 = "nDgf33f" fullword ascii /* score: '4.00'*/
      $s104 = "kuuTa@<" fullword ascii /* score: '4.00'*/
      $s105 = "RxANR_3" fullword ascii /* score: '4.00'*/
      $s106 = "cFDg'KB" fullword ascii /* score: '4.00'*/
      $s107 = "kGbVUVRin" fullword ascii /* score: '4.00'*/
      $s108 = "iaEFmGX" fullword ascii /* score: '4.00'*/
      $s109 = "hagq!x" fullword ascii /* score: '4.00'*/
      $s110 = "&Ohde]If" fullword ascii /* score: '4.00'*/
      $s111 = "PIoF \"" fullword ascii /* score: '4.00'*/
      $s112 = "TFBpU4#I" fullword ascii /* score: '4.00'*/
      $s113 = "9|EaPgZ$3" fullword ascii /* score: '4.00'*/
      $s114 = "tJiCf@A" fullword ascii /* score: '4.00'*/
      $s115 = "bWws!Q" fullword ascii /* score: '4.00'*/
      $s116 = "JAHw^FP" fullword ascii /* score: '4.00'*/
      $s117 = "JkZkrkHnCC" fullword ascii /* score: '4.00'*/
      $s118 = "tDml\"P" fullword ascii /* score: '4.00'*/
      $s119 = "xZdG@~b=:a?K" fullword ascii /* score: '4.00'*/
      $s120 = "YtiyH\\" fullword ascii /* score: '4.00'*/
      $s121 = "IQBK'TK6:J" fullword ascii /* score: '4.00'*/
      $s122 = "Hv&zrztzvz" fullword ascii /* score: '4.00'*/
      $s123 = "pyjd)j[" fullword ascii /* score: '4.00'*/
      $s124 = "Rjcs:Dw" fullword ascii /* score: '4.00'*/
      $s125 = "js/pdiO$DR" fullword ascii /* score: '4.00'*/
      $s126 = "mOUOJgj" fullword ascii /* score: '4.00'*/
      $s127 = "nUIL4vq" fullword ascii /* score: '4.00'*/
      $s128 = "LwHa*?(O" fullword ascii /* score: '4.00'*/
      $s129 = "zoqDPo]%$" fullword ascii /* score: '4.00'*/
      $s130 = "AtIss@qfs/" fullword ascii /* score: '4.00'*/
      $s131 = "y.IuB=`\\" fullword ascii /* score: '4.00'*/
      $s132 = "mxyDND4]" fullword ascii /* score: '4.00'*/
      $s133 = "LHzv)jD" fullword ascii /* score: '4.00'*/
      $s134 = "duljN'I" fullword ascii /* score: '4.00'*/
      $s135 = "jrnf]!gf" fullword ascii /* score: '4.00'*/
      $s136 = "kJLE %$\"W~" fullword ascii /* score: '4.00'*/
      $s137 = ".FpV.2D" fullword ascii /* score: '4.00'*/
      $s138 = "zSVVRq|" fullword ascii /* score: '4.00'*/
      $s139 = "cGnfaMc" fullword ascii /* score: '4.00'*/
      $s140 = "PdODg*." fullword ascii /* score: '4.00'*/
      $s141 = "o~XipJy|;" fullword ascii /* score: '4.00'*/
      $s142 = ")PtKc\\c" fullword ascii /* score: '4.00'*/
      $s143 = "!.BDP<G" fullword ascii /* score: '4.00'*/
      $s144 = "WCVlBe@|" fullword ascii /* score: '4.00'*/
      $s145 = "VPdF|cE" fullword ascii /* score: '4.00'*/
      $s146 = "EFzy?A" fullword ascii /* score: '4.00'*/
      $s147 = "            <!--This Id value indicates the application supports Windows 7/Server 2008 R2 functionality-->" fullword ascii /* score: '3.00'*/
      $s148 = "D$HjDj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s149 = "00(0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s150 = ":<\\u6:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s151 = "SSh`2@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s152 = "33(313F3[3h3p3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s153 = "<At <Bt" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s154 = "            <!--This Id value indicates the application supports Windows 8/Server 2012 functionality-->" fullword ascii /* score: '3.00'*/
      $s155 = "          level=\"asInvoker\"" fullword ascii /* score: '3.00'*/
      $s156 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii /* score: '2.00'*/
      $s157 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " fullword ascii /* score: '2.00'*/
      $s158 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s159 = "\\DpQ-L_F" fullword ascii /* score: '2.00'*/
      $s160 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii /* score: '2.00'*/
      $s161 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii /* score: '2.00'*/
      $s162 = "PA<None>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s163 = "    </compatibility>" fullword ascii /* score: '2.00'*/
      $s164 = "5D5S5c5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s165 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s166 = "CVsC31" fullword ascii /* score: '2.00'*/
      $s167 = "\\% QWL" fullword ascii /* score: '2.00'*/
      $s168 = "\\XNf3r" fullword ascii /* score: '2.00'*/
      $s169 = ":bEyE~" fullword ascii /* score: '2.00'*/
      $s170 = "\\=tqJJ" fullword ascii /* score: '2.00'*/
      $s171 = "llocx3" fullword ascii /* score: '2.00'*/
      $s172 = "knjQ35" fullword ascii /* score: '2.00'*/
      $s173 = "\\DBPXX" fullword ascii /* score: '2.00'*/
      $s174 = "\\\\u gz" fullword ascii /* score: '2.00'*/
      $s175 = "BWXty3" fullword ascii /* score: '2.00'*/
      $s176 = "\\Q9kw0F0" fullword ascii /* score: '2.00'*/
      $s177 = "oXuQu9" fullword ascii /* score: '2.00'*/
      $s178 = "\\k(OG`" fullword ascii /* score: '2.00'*/
      $s179 = "gqetr8" fullword ascii /* score: '2.00'*/
      $s180 = "\\Mknd'" fullword ascii /* score: '2.00'*/
      $s181 = "\\t*.u5" fullword ascii /* score: '2.00'*/
      $s182 = "79+upM" fullword ascii /* score: '1.00'*/
      $s183 = "!2MQC{b" fullword ascii /* score: '1.00'*/
      $s184 = "X1'@)y" fullword ascii /* score: '1.00'*/
      $s185 = "0(0K0f0" fullword ascii /* score: '1.00'*/
      $s186 = "ATJ&Nb" fullword ascii /* score: '1.00'*/
      $s187 = "+|[9GS5" fullword ascii /* score: '1.00'*/
      $s188 = "/O(,\"K" fullword ascii /* score: '1.00'*/
      $s189 = "}9'(UQ" fullword ascii /* score: '1.00'*/
      $s190 = "<.|@(0" fullword ascii /* score: '1.00'*/
      $s191 = "#qCqFX" fullword ascii /* score: '1.00'*/
      $s192 = "/@t0X=" fullword ascii /* score: '1.00'*/
      $s193 = ":+:1:D:L:" fullword ascii /* score: '1.00'*/
      $s194 = "pM$mEV" fullword ascii /* score: '1.00'*/
      $s195 = " kcv/Z^" fullword ascii /* score: '1.00'*/
      $s196 = "=qC^Qb" fullword ascii /* score: '1.00'*/
      $s197 = "<.<E<M<V<[<`<v<|<" fullword ascii /* score: '1.00'*/
      $s198 = "rR|Vyr" fullword ascii /* score: '1.00'*/
      $s199 = "a2440225f93a" ascii /* score: '1.00'*/
      $s200 = "QAu^GJ" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6 {
   meta:
      description = "Amadey_MALW - file 707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6"
   strings:
      $s1 = "y87aW57.exe" fullword ascii /* score: '19.00'*/
      $s2 = "za116222.exe" fullword ascii /* score: '19.00'*/
      $s3 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s4 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s6 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s7 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s8 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s9 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwrw" fullword ascii /* score: '8.00'*/
      $s11 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii /* score: '7.00'*/
      $s12 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii /* score: '7.00'*/
      $s13 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii /* score: '7.00'*/
      $s14 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s15 = "&l&j:\\u" fullword ascii /* score: '7.00'*/
      $s16 = "h70.SdH" fullword ascii /* score: '7.00'*/
      $s17 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s18 = "UUUUTUU" fullword ascii /* score: '6.50'*/
      $s19 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii /* score: '6.50'*/
      $s20 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s21 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s22 = "RSDSwb6" fullword ascii /* score: '5.00'*/
      $s23 = "IPwhnD7" fullword ascii /* score: '5.00'*/
      $s24 = "fucbjc" fullword ascii /* score: '5.00'*/
      $s25 = " -@Chi" fullword ascii /* score: '5.00'*/
      $s26 = "05- Q," fullword ascii /* score: '5.00'*/
      $s27 = "99oU* Z" fullword ascii /* score: '5.00'*/
      $s28 = "hM* lI" fullword ascii /* score: '5.00'*/
      $s29 = "+ K7v:9FR" fullword ascii /* score: '5.00'*/
      $s30 = "+ U{IYa-7O" fullword ascii /* score: '5.00'*/
      $s31 = "+%t%_x" fullword ascii /* score: '5.00'*/
      $s32 = "O -rf&" fullword ascii /* score: '5.00'*/
      $s33 = "e}'?+ " fullword ascii /* score: '5.00'*/
      $s34 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s35 = "Extracting" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 13 times */
      $s36 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s37 = "Extract" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 42 times */
      $s38 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s39 = "PendingFileRenameOperations" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 52 times */
      $s40 = "RegServer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.94'*/ /* Goodware String - occured 57 times */
      $s41 = "Reboot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 105 times */
      $s42 = "SeShutdownPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s43 = "Internet Explorer" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s44 = "=\">>>G>R>Y>p>v>|>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s45 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s46 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s47 = "?+?1?<?B?N?^?g?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s48 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s49 = "?e?q?}?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s50 = ".rdata$brc" fullword ascii /* score: '4.00'*/
      $s51 = "WWj WWWSW" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s52 = ";#;/;5;<;E;K;S;Y;f;n;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s53 = "11.00.14393.0 (rs1_release.160715-1616)" fullword wide /* score: '4.00'*/
      $s54 = "WEXTRACT.EXE            .MUI" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s55 = "pAWB+5eJ" fullword ascii /* score: '4.00'*/
      $s56 = "UYInq5;" fullword ascii /* score: '4.00'*/
      $s57 = "5.IEv," fullword ascii /* score: '4.00'*/
      $s58 = "nfbXN1D+@sc5" fullword ascii /* score: '4.00'*/
      $s59 = "wlmo|)}" fullword ascii /* score: '4.00'*/
      $s60 = "oKJAntZI" fullword ascii /* score: '4.00'*/
      $s61 = "vEbSw2!" fullword ascii /* score: '4.00'*/
      $s62 = "qPxj!4" fullword ascii /* score: '4.00'*/
      $s63 = "=`.UVM}" fullword ascii /* score: '4.00'*/
      $s64 = "HNtd7}t" fullword ascii /* score: '4.00'*/
      $s65 = "crgqk2NO" fullword ascii /* score: '4.00'*/
      $s66 = ")fWhfhVf0" fullword ascii /* score: '4.00'*/
      $s67 = "AhrHKq!Rj" fullword ascii /* score: '4.00'*/
      $s68 = "uuhJK0a" fullword ascii /* score: '4.00'*/
      $s69 = "VeveE[~P" fullword ascii /* score: '4.00'*/
      $s70 = "=hOeO!" fullword ascii /* score: '4.00'*/
      $s71 = "e3VEWu\\G" fullword ascii /* score: '4.00'*/
      $s72 = "@bFjv`b@t" fullword ascii /* score: '4.00'*/
      $s73 = "VeAC7LF." fullword ascii /* score: '4.00'*/
      $s74 = "U=UUUUUUUUVU" fullword ascii /* score: '4.00'*/
      $s75 = "TwLT4,)KW*" fullword ascii /* score: '4.00'*/
      $s76 = "vGIJ%.9." fullword ascii /* score: '4.00'*/
      $s77 = "bwSh2KK" fullword ascii /* score: '4.00'*/
      $s78 = "cVrg/\"" fullword ascii /* score: '4.00'*/
      $s79 = ".EAn;K" fullword ascii /* score: '4.00'*/
      $s80 = "UUTu#3ET" fullword ascii /* score: '4.00'*/
      $s81 = "G.lLy;" fullword ascii /* score: '4.00'*/
      $s82 = "FsgJ7=." fullword ascii /* score: '4.00'*/
      $s83 = "wqqTn<D^L@#" fullword ascii /* score: '4.00'*/
      $s84 = " Qe.hys{" fullword ascii /* score: '4.00'*/
      $s85 = "XpJOTC6w" fullword ascii /* score: '4.00'*/
      $s86 = "fkZM*Y(" fullword ascii /* score: '4.00'*/
      $s87 = "qboNSw~" fullword ascii /* score: '4.00'*/
      $s88 = "cTOw]TZ" fullword ascii /* score: '4.00'*/
      $s89 = "ISxq8t@" fullword ascii /* score: '4.00'*/
      $s90 = "cyjemd]" fullword ascii /* score: '4.00'*/
      $s91 = "=oeSq/.Zb=(h" fullword ascii /* score: '4.00'*/
      $s92 = "XkRl8aU" fullword ascii /* score: '4.00'*/
      $s93 = "kxbkuHZW" fullword ascii /* score: '4.00'*/
      $s94 = "xDQFgSA" fullword ascii /* score: '4.00'*/
      $s95 = "rHqIBdg" fullword ascii /* score: '4.00'*/
      $s96 = "WYtq&h3" fullword ascii /* score: '4.00'*/
      $s97 = "VFKk38'" fullword ascii /* score: '4.00'*/
      $s98 = "eDyqY\\;" fullword ascii /* score: '4.00'*/
      $s99 = "GmTcj\\\\" fullword ascii /* score: '4.00'*/
      $s100 = "WwUiFs<!" fullword ascii /* score: '4.00'*/
      $s101 = "TKYP|$)" fullword ascii /* score: '4.00'*/
      $s102 = "pNHL>jC" fullword ascii /* score: '4.00'*/
      $s103 = "MpXIQsj" fullword ascii /* score: '4.00'*/
      $s104 = "pXLD,1;" fullword ascii /* score: '4.00'*/
      $s105 = "grFt$`F" fullword ascii /* score: '4.00'*/
      $s106 = "%d6%S@e`w}" fullword ascii /* score: '4.00'*/
      $s107 = "cR9LFVK~'N" fullword ascii /* score: '4.00'*/
      $s108 = "SDpz]nd" fullword ascii /* score: '4.00'*/
      $s109 = "gCtE4%V" fullword ascii /* score: '4.00'*/
      $s110 = "Sbky5Kl" fullword ascii /* score: '4.00'*/
      $s111 = "b4m}WMTnVqi" fullword ascii /* score: '4.00'*/
      $s112 = "EQsf>7c" fullword ascii /* score: '4.00'*/
      $s113 = "OkWUWfK#" fullword ascii /* score: '4.00'*/
      $s114 = "XAUNNDr" fullword ascii /* score: '4.00'*/
      $s115 = "WaWc_FC," fullword ascii /* score: '4.00'*/
      $s116 = ")AUDEL\\k" fullword ascii /* score: '4.00'*/
      $s117 = "IIFL+Xv" fullword ascii /* score: '4.00'*/
      $s118 = "wwwwwwwwwwww.v" fullword ascii /* score: '4.00'*/
      $s119 = "<0jsLBt}C*}" fullword ascii /* score: '4.00'*/
      $s120 = "ynIB8c`" fullword ascii /* score: '4.00'*/
      $s121 = "KOtFu?p" fullword ascii /* score: '4.00'*/
      $s122 = "mRUchMO" fullword ascii /* score: '4.00'*/
      $s123 = "UzNGZwsL" fullword ascii /* score: '4.00'*/
      $s124 = "ZWZHYR^" fullword ascii /* score: '4.00'*/
      $s125 = "reQHi8.j" fullword ascii /* score: '4.00'*/
      $s126 = "fYPa+81" fullword ascii /* score: '4.00'*/
      $s127 = "YSYek~Cl" fullword ascii /* score: '4.00'*/
      $s128 = "sq.fPF>" fullword ascii /* score: '4.00'*/
      $s129 = "\"?lMBz}h*" fullword ascii /* score: '4.00'*/
      $s130 = "M;5.KNw^" fullword ascii /* score: '4.00'*/
      $s131 = "_V]OISf?" fullword ascii /* score: '4.00'*/
      $s132 = "vncw5Dw" fullword ascii /* score: '4.00'*/
      $s133 = "'UqakHfF" fullword ascii /* score: '4.00'*/
      $s134 = "mpAwYt " fullword ascii /* score: '4.00'*/
      $s135 = "I~%c;,A3" fullword ascii /* score: '3.50'*/
      $s136 = "            <!--This Id value indicates the application supports Windows 7/Server 2008 R2 functionality-->" fullword ascii /* score: '3.00'*/
      $s137 = "D$HjDj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s138 = "00(0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s139 = ":<\\u6:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s140 = "SSh`2@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s141 = "33(313F3[3h3p3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s142 = "<At <Bt" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s143 = "            <!--This Id value indicates the application supports Windows 8/Server 2012 functionality-->" fullword ascii /* score: '3.00'*/
      $s144 = "          level=\"asInvoker\"" fullword ascii /* score: '3.00'*/
      $s145 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii /* score: '2.00'*/
      $s146 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " fullword ascii /* score: '2.00'*/
      $s147 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s148 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii /* score: '2.00'*/
      $s149 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii /* score: '2.00'*/
      $s150 = "PA<None>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s151 = "    </compatibility>" fullword ascii /* score: '2.00'*/
      $s152 = "5D5S5c5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s153 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s154 = "jpWrI6" fullword ascii /* score: '2.00'*/
      $s155 = "tKWLh5" fullword ascii /* score: '2.00'*/
      $s156 = "jNBRJ0" fullword ascii /* score: '2.00'*/
      $s157 = "JuYUI0" fullword ascii /* score: '2.00'*/
      $s158 = "\\VSq9=" fullword ascii /* score: '2.00'*/
      $s159 = "\\ga\"&h" fullword ascii /* score: '2.00'*/
      $s160 = "\\w+9:WV" fullword ascii /* score: '2.00'*/
      $s161 = "\\[msX60" fullword ascii /* score: '2.00'*/
      $s162 = "\\ idh\\" fullword ascii /* score: '2.00'*/
      $s163 = "\\FV<W1" fullword ascii /* score: '2.00'*/
      $s164 = "\\OD7EE" fullword ascii /* score: '2.00'*/
      $s165 = "IrI152" fullword ascii /* score: '2.00'*/
      $s166 = "gsWdu2" fullword ascii /* score: '2.00'*/
      $s167 = "\\cwp>i}" fullword ascii /* score: '2.00'*/
      $s168 = "oHYyV9" fullword ascii /* score: '2.00'*/
      $s169 = "RLEQw9" fullword ascii /* score: '2.00'*/
      $s170 = "\\Vnk'Am" fullword ascii /* score: '2.00'*/
      $s171 = "DKkL40" fullword ascii /* score: '2.00'*/
      $s172 = "\\XaH:o" fullword ascii /* score: '2.00'*/
      $s173 = "Msgxg3" fullword ascii /* score: '2.00'*/
      $s174 = "0(0K0f0" fullword ascii /* score: '1.00'*/
      $s175 = ":+:1:D:L:" fullword ascii /* score: '1.00'*/
      $s176 = "<.<E<M<V<[<`<v<|<" fullword ascii /* score: '1.00'*/
      $s177 = "a2440225f93a" ascii /* score: '1.00'*/
      $s178 = "3)40494D4`4" fullword ascii /* score: '1.00'*/
      $s179 = ":6:N:S:r:" fullword ascii /* score: '1.00'*/
      $s180 = "=\"=(=2=M={=" fullword ascii /* score: '1.00'*/
      $s181 = "?(?9?H?W?c?y?" fullword ascii /* score: '1.00'*/
      $s182 = "3$303f3r3~3" fullword ascii /* score: '1.00'*/
      $s183 = "8&8,878R8^8|8" fullword ascii /* score: '1.00'*/
      $s184 = "60L0_0k0r0" fullword ascii /* score: '1.00'*/
      $s185 = "0W0j0p0x0" fullword ascii /* score: '1.00'*/
      $s186 = "6#676>6D6K6P6W6_6d6" fullword ascii /* score: '1.00'*/
      $s187 = "9*:::G:c:l:~:" fullword ascii /* score: '1.00'*/
      $s188 = "; <*<0<6<<<D<J<V<" fullword ascii /* score: '1.00'*/
      $s189 = "6%6J6d6" fullword ascii /* score: '1.00'*/
      $s190 = "t3WWh@1@" fullword ascii /* score: '1.00'*/
      $s191 = "3>3]3p3" fullword ascii /* score: '1.00'*/
      $s192 = "=2=\\=k=y=" fullword ascii /* score: '1.00'*/
      $s193 = "<9<H<N<W<^<s<" fullword ascii /* score: '1.00'*/
      $s194 = "0,121}1" fullword ascii /* score: '1.00'*/
      $s195 = "<<<`<o<|<" fullword ascii /* score: '1.00'*/
      $s196 = "6595b64144ccf1df" ascii /* score: '1.00'*/
      $s197 = "1'1-13181?1O1Z1`1x1" fullword ascii /* score: '1.00'*/
      $s198 = "0$0*030H0N0m0x0" fullword ascii /* score: '1.00'*/
      $s199 = "1.191@1K1]1f1" fullword ascii /* score: '1.00'*/
      $s200 = ">!?(?G?R?g?" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10 {
   meta:
      description = "Amadey_MALW - file ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10"
   strings:
      $s1 = "za912166.exe" fullword ascii /* score: '19.00'*/
      $s2 = "y04Gd06.exe" fullword ascii /* score: '19.00'*/
      $s3 = "GW.exe" fullword ascii /* score: '16.00'*/
      $s4 = "UEdfTTVC(" fullword ascii /* base64 encoded string 'PG_M5B' */ /* score: '14.00'*/
      $s5 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s6 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s7 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s8 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s9 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s10 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s11 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s12 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii /* score: '7.00'*/
      $s13 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii /* score: '7.00'*/
      $s14 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii /* score: '7.00'*/
      $s15 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s16 = "UOt:\"L\"Z (" fullword ascii /* score: '7.00'*/
      $s17 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s18 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s19 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii /* score: '6.50'*/
      $s20 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s21 = "RSDSwb6" fullword ascii /* score: '5.00'*/
      $s22 = "slmslm" fullword ascii /* score: '5.00'*/
      $s23 = "Nla8+ i" fullword ascii /* score: '5.00'*/
      $s24 = "/_vB- " fullword ascii /* score: '5.00'*/
      $s25 = "# bpEU" fullword ascii /* score: '5.00'*/
      $s26 = " -EAE%" fullword ascii /* score: '5.00'*/
      $s27 = "/- ~0>!Z" fullword ascii /* score: '5.00'*/
      $s28 = "s+ 7Sl" fullword ascii /* score: '5.00'*/
      $s29 = "# zs$o#" fullword ascii /* score: '5.00'*/
      $s30 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s31 = "Extracting" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 13 times */
      $s32 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s33 = "Extract" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 42 times */
      $s34 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s35 = "PendingFileRenameOperations" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 52 times */
      $s36 = "RegServer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.94'*/ /* Goodware String - occured 57 times */
      $s37 = "Reboot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 105 times */
      $s38 = "SeShutdownPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s39 = "Internet Explorer" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s40 = "=\">>>G>R>Y>p>v>|>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s41 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s42 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s43 = "?+?1?<?B?N?^?g?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s44 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s45 = "QANL(6N" fullword ascii /* score: '4.00'*/
      $s46 = "?e?q?}?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s47 = ".rdata$brc" fullword ascii /* score: '4.00'*/
      $s48 = "WWj WWWSW" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s49 = "CIdwj,U@-7d" fullword ascii /* score: '4.00'*/
      $s50 = ";#;/;5;<;E;K;S;Y;f;n;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s51 = "11.00.14393.0 (rs1_release.160715-1616)" fullword wide /* score: '4.00'*/
      $s52 = "WEXTRACT.EXE            .MUI" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s53 = "LUFk >O" fullword ascii /* score: '4.00'*/
      $s54 = "RrEe>LI" fullword ascii /* score: '4.00'*/
      $s55 = "YGJC&meA" fullword ascii /* score: '4.00'*/
      $s56 = "UUUUUUUUUUUUUUUUUW=TUUUUPU4#" fullword ascii /* score: '4.00'*/
      $s57 = "FNDb,,!" fullword ascii /* score: '4.00'*/
      $s58 = "cyIt~Qc" fullword ascii /* score: '4.00'*/
      $s59 = "2TiKq{aw" fullword ascii /* score: '4.00'*/
      $s60 = "irhuO/Fs^" fullword ascii /* score: '4.00'*/
      $s61 = "pftBFyMcOL" fullword ascii /* score: '4.00'*/
      $s62 = "KIes\\K" fullword ascii /* score: '4.00'*/
      $s63 = "uXhw25&" fullword ascii /* score: '4.00'*/
      $s64 = "/BzUuh+c" fullword ascii /* score: '4.00'*/
      $s65 = "sCpKKrP" fullword ascii /* score: '4.00'*/
      $s66 = "'\\rAMaAS9PLN-\\r" fullword ascii /* score: '4.00'*/
      $s67 = "JTIWYQ;" fullword ascii /* score: '4.00'*/
      $s68 = "DHCRa4W" fullword ascii /* score: '4.00'*/
      $s69 = "IqlCiMY" fullword ascii /* score: '4.00'*/
      $s70 = "MVcQVYz" fullword ascii /* score: '4.00'*/
      $s71 = "wjvzZ v8" fullword ascii /* score: '4.00'*/
      $s72 = "rqAxm\"mt" fullword ascii /* score: '4.00'*/
      $s73 = "!lGFr&:-" fullword ascii /* score: '4.00'*/
      $s74 = "x7%s6$" fullword ascii /* score: '4.00'*/
      $s75 = "XDqU&q$" fullword ascii /* score: '4.00'*/
      $s76 = "KMlB+:%" fullword ascii /* score: '4.00'*/
      $s77 = "##d5gGUvFDzp" fullword ascii /* score: '4.00'*/
      $s78 = "1sAln5j>" fullword ascii /* score: '4.00'*/
      $s79 = ".%s9J9`" fullword ascii /* score: '4.00'*/
      $s80 = "C\"Wmct2~b" fullword ascii /* score: '4.00'*/
      $s81 = "jlYX6^i" fullword ascii /* score: '4.00'*/
      $s82 = "{gHdS+K_" fullword ascii /* score: '4.00'*/
      $s83 = ".Wcq)r" fullword ascii /* score: '4.00'*/
      $s84 = "Wnvt1c'" fullword ascii /* score: '4.00'*/
      $s85 = "ufDl5JAf" fullword ascii /* score: '4.00'*/
      $s86 = "qOiW\\Bh" fullword ascii /* score: '4.00'*/
      $s87 = "joLii0e" fullword ascii /* score: '4.00'*/
      $s88 = "oFYz<ZO" fullword ascii /* score: '4.00'*/
      $s89 = "5\"UuWgUfpF$e" fullword ascii /* score: '4.00'*/
      $s90 = "~.erq}" fullword ascii /* score: '4.00'*/
      $s91 = "UgRUV#`" fullword ascii /* score: '4.00'*/
      $s92 = "}zQUT\\)" fullword ascii /* score: '4.00'*/
      $s93 = "SsStTE*" fullword ascii /* score: '4.00'*/
      $s94 = "HmaFr_ZJs" fullword ascii /* score: '4.00'*/
      $s95 = "4uasCz+W" fullword ascii /* score: '4.00'*/
      $s96 = "<jkqO\"MzD" fullword ascii /* score: '4.00'*/
      $s97 = "hBJni$G" fullword ascii /* score: '4.00'*/
      $s98 = "keRY=6Q" fullword ascii /* score: '4.00'*/
      $s99 = ".pNf@v" fullword ascii /* score: '4.00'*/
      $s100 = "xIgPD!" fullword ascii /* score: '4.00'*/
      $s101 = "eXql?x~" fullword ascii /* score: '4.00'*/
      $s102 = " XaSP!" fullword ascii /* score: '4.00'*/
      $s103 = "HOXqF(4>" fullword ascii /* score: '4.00'*/
      $s104 = "eYieiqjcX" fullword ascii /* score: '4.00'*/
      $s105 = "veCTE2r`" fullword ascii /* score: '4.00'*/
      $s106 = "osQS2_T" fullword ascii /* score: '4.00'*/
      $s107 = "OmWlW?" fullword ascii /* score: '4.00'*/
      $s108 = "wwZL?Z" fullword ascii /* score: '4.00'*/
      $s109 = "KmLS4{A" fullword ascii /* score: '4.00'*/
      $s110 = "GPfVF9S" fullword ascii /* score: '4.00'*/
      $s111 = "KEEEy!" fullword ascii /* score: '4.00'*/
      $s112 = "NJiqE$o" fullword ascii /* score: '4.00'*/
      $s113 = "BASn|VKc" fullword ascii /* score: '4.00'*/
      $s114 = "tCDS\"h?v~1" fullword ascii /* score: '4.00'*/
      $s115 = "JguPHZ#T5" fullword ascii /* score: '4.00'*/
      $s116 = "RNAXh7{M" fullword ascii /* score: '4.00'*/
      $s117 = "oPzss?Do" fullword ascii /* score: '4.00'*/
      $s118 = "AGpop8.M" fullword ascii /* score: '4.00'*/
      $s119 = "Zempz9V(" fullword ascii /* score: '4.00'*/
      $s120 = "mVeceD," fullword ascii /* score: '4.00'*/
      $s121 = "ffffsffWffffffvf" fullword ascii /* score: '4.00'*/
      $s122 = "r[dzFzK72" fullword ascii /* score: '4.00'*/
      $s123 = "Mv.TuT" fullword ascii /* score: '4.00'*/
      $s124 = "VZFSJ<r" fullword ascii /* score: '4.00'*/
      $s125 = "WrxS=$a" fullword ascii /* score: '4.00'*/
      $s126 = "qHLRD]pl" fullword ascii /* score: '4.00'*/
      $s127 = "kwSM0Q9-" fullword ascii /* score: '4.00'*/
      $s128 = "FfrI?@" fullword ascii /* score: '4.00'*/
      $s129 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s130 = "&EBIu\\kO" fullword ascii /* score: '4.00'*/
      $s131 = "g>ALvA!" fullword ascii /* score: '4.00'*/
      $s132 = "ghbO!X}" fullword ascii /* score: '4.00'*/
      $s133 = "wNUPB?" fullword ascii /* score: '4.00'*/
      $s134 = "LLvD6e'" fullword ascii /* score: '4.00'*/
      $s135 = "ZyqX`dk" fullword ascii /* score: '4.00'*/
      $s136 = "RURTRZ" fullword ascii /* score: '3.50'*/
      $s137 = "UTTRZA" fullword ascii /* score: '3.50'*/
      $s138 = "UUUUTU" fullword ascii /* score: '3.50'*/
      $s139 = "            <!--This Id value indicates the application supports Windows 7/Server 2008 R2 functionality-->" fullword ascii /* score: '3.00'*/
      $s140 = "D$HjDj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s141 = "00(0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s142 = ":<\\u6:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s143 = "SSh`2@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s144 = "33(313F3[3h3p3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s145 = "<At <Bt" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s146 = "            <!--This Id value indicates the application supports Windows 8/Server 2012 functionality-->" fullword ascii /* score: '3.00'*/
      $s147 = "          level=\"asInvoker\"" fullword ascii /* score: '3.00'*/
      $s148 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii /* score: '2.00'*/
      $s149 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " fullword ascii /* score: '2.00'*/
      $s150 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s151 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii /* score: '2.00'*/
      $s152 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii /* score: '2.00'*/
      $s153 = "PA<None>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s154 = "    </compatibility>" fullword ascii /* score: '2.00'*/
      $s155 = "5D5S5c5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s156 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s157 = "\\[isH7P" fullword ascii /* score: '2.00'*/
      $s158 = "\\rR\"0r9" fullword ascii /* score: '2.00'*/
      $s159 = "\\vVV |" fullword ascii /* score: '2.00'*/
      $s160 = "\\C[+-D%" fullword ascii /* score: '2.00'*/
      $s161 = "\\nWpM~m" fullword ascii /* score: '2.00'*/
      $s162 = "\\# 'x(" fullword ascii /* score: '2.00'*/
      $s163 = "VzuQB4" fullword ascii /* score: '2.00'*/
      $s164 = "YzDes6" fullword ascii /* score: '2.00'*/
      $s165 = "\\;l'O}Y" fullword ascii /* score: '2.00'*/
      $s166 = "YeYfV5" fullword ascii /* score: '2.00'*/
      $s167 = "\\\\yJ\\+" fullword ascii /* score: '2.00'*/
      $s168 = "sLmJG1" fullword ascii /* score: '2.00'*/
      $s169 = "\\CyXO;" fullword ascii /* score: '2.00'*/
      $s170 = "ruYSx2" fullword ascii /* score: '2.00'*/
      $s171 = "\\]Kv'-" fullword ascii /* score: '2.00'*/
      $s172 = "\\5O^;D|" fullword ascii /* score: '2.00'*/
      $s173 = "\\Q;HV;" fullword ascii /* score: '2.00'*/
      $s174 = "\\3_zh4" fullword ascii /* score: '2.00'*/
      $s175 = "OuqI79" fullword ascii /* score: '2.00'*/
      $s176 = "\\=o&_z'" fullword ascii /* score: '2.00'*/
      $s177 = "\\f##c " fullword ascii /* score: '2.00'*/
      $s178 = "HpcKE8" fullword ascii /* score: '2.00'*/
      $s179 = "ETubC3" fullword ascii /* score: '2.00'*/
      $s180 = "pUXLh6" fullword ascii /* score: '2.00'*/
      $s181 = "0(0K0f0" fullword ascii /* score: '1.00'*/
      $s182 = "gd;-;.*" fullword ascii /* score: '1.00'*/
      $s183 = ":+:1:D:L:" fullword ascii /* score: '1.00'*/
      $s184 = "<.<E<M<V<[<`<v<|<" fullword ascii /* score: '1.00'*/
      $s185 = "a2440225f93a" ascii /* score: '1.00'*/
      $s186 = "oK]~Yr" fullword ascii /* score: '1.00'*/
      $s187 = "3)40494D4`4" fullword ascii /* score: '1.00'*/
      $s188 = ":6:N:S:r:" fullword ascii /* score: '1.00'*/
      $s189 = "=\"=(=2=M={=" fullword ascii /* score: '1.00'*/
      $s190 = "?(?9?H?W?c?y?" fullword ascii /* score: '1.00'*/
      $s191 = "3$303f3r3~3" fullword ascii /* score: '1.00'*/
      $s192 = "8&8,878R8^8|8" fullword ascii /* score: '1.00'*/
      $s193 = "60L0_0k0r0" fullword ascii /* score: '1.00'*/
      $s194 = "0W0j0p0x0" fullword ascii /* score: '1.00'*/
      $s195 = "6#676>6D6K6P6W6_6d6" fullword ascii /* score: '1.00'*/
      $s196 = "9*:::G:c:l:~:" fullword ascii /* score: '1.00'*/
      $s197 = "; <*<0<6<<<D<J<V<" fullword ascii /* score: '1.00'*/
      $s198 = "6%6J6d6" fullword ascii /* score: '1.00'*/
      $s199 = "t3WWh@1@" fullword ascii /* score: '1.00'*/
      $s200 = "3LKU 4@x" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515 {
   meta:
      description = "Amadey_MALW - file 4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
   strings:
      $s1 = "xHRuL30.exe" fullword ascii /* score: '22.00'*/
      $s2 = "za161252.exe" fullword ascii /* score: '19.00'*/
      $s3 = "za420059.exe" fullword ascii /* score: '19.00'*/
      $s4 = "y15Jg93.exe" fullword ascii /* score: '19.00'*/
      $s5 = "v0017Qj.exe" fullword ascii /* score: '19.00'*/
      $s6 = "tz9483.exe" fullword ascii /* score: '19.00'*/
      $s7 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s8 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s9 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s10 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s11 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s12 = "* ?}-C" fullword ascii /* score: '9.00'*/
      $s13 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s14 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s15 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii /* score: '7.00'*/
      $s16 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii /* score: '7.00'*/
      $s17 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii /* score: '7.00'*/
      $s18 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s19 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s20 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s21 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s22 = "RSDSwb6" fullword ascii /* score: '5.00'*/
      $s23 = "- m4}g" fullword ascii /* score: '5.00'*/
      $s24 = "Ed9|- " fullword ascii /* score: '5.00'*/
      $s25 = " ' + /" fullword ascii /* score: '5.00'*/
      $s26 = "- jQzba" fullword ascii /* score: '5.00'*/
      $s27 = "%v%=V'" fullword ascii /* score: '5.00'*/
      $s28 = "%Vw%(Km" fullword ascii /* score: '5.00'*/
      $s29 = "rug+ N" fullword ascii /* score: '5.00'*/
      $s30 = "[%J%L\"r" fullword ascii /* score: '5.00'*/
      $s31 = "#  ~#W" fullword ascii /* score: '5.00'*/
      $s32 = "\\jRKH{><" fullword ascii /* score: '5.00'*/
      $s33 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s34 = "Extracting" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 13 times */
      $s35 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s36 = "Extract" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 42 times */
      $s37 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s38 = "PendingFileRenameOperations" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 52 times */
      $s39 = "RegServer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.94'*/ /* Goodware String - occured 57 times */
      $s40 = "Reboot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 105 times */
      $s41 = "SeShutdownPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s42 = "Internet Explorer" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s43 = "=\">>>G>R>Y>p>v>|>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s44 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s45 = "jYVp!G:" fullword ascii /* score: '4.00'*/
      $s46 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s47 = "?+?1?<?B?N?^?g?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s48 = "qxfKApWJR;" fullword ascii /* score: '4.00'*/
      $s49 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s50 = "Fhrfa\"" fullword ascii /* score: '4.00'*/
      $s51 = "?e?q?}?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s52 = ".rdata$brc" fullword ascii /* score: '4.00'*/
      $s53 = "WWj WWWSW" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s54 = "CIdwj,U@-7d" fullword ascii /* score: '4.00'*/
      $s55 = ";#;/;5;<;E;K;S;Y;f;n;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s56 = "11.00.14393.0 (rs1_release.160715-1616)" fullword wide /* score: '4.00'*/
      $s57 = "WEXTRACT.EXE            .MUI" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s58 = "uGjOV)xA" fullword ascii /* score: '4.00'*/
      $s59 = "rgsVoXh" fullword ascii /* score: '4.00'*/
      $s60 = "UUUUUUUUUUUUUUUUU]UUUUUU" fullword ascii /* score: '4.00'*/
      $s61 = "rApv=.3" fullword ascii /* score: '4.00'*/
      $s62 = "NkRL!~M" fullword ascii /* score: '4.00'*/
      $s63 = "dKuKq1&" fullword ascii /* score: '4.00'*/
      $s64 = "xLbXp='" fullword ascii /* score: '4.00'*/
      $s65 = "sVpv&4I>" fullword ascii /* score: '4.00'*/
      $s66 = "CIbuh*S>-7d" fullword ascii /* score: '4.00'*/
      $s67 = "FDtUYem" fullword ascii /* score: '4.00'*/
      $s68 = "gWUPUnu" fullword ascii /* score: '4.00'*/
      $s69 = "QQ.sbt" fullword ascii /* score: '4.00'*/
      $s70 = "#TGbGlGbB" fullword ascii /* score: '4.00'*/
      $s71 = "3:YhSq!p" fullword ascii /* score: '4.00'*/
      $s72 = "cJWyu[x" fullword ascii /* score: '4.00'*/
      $s73 = "BdvpnjU" fullword ascii /* score: '4.00'*/
      $s74 = "2rsBkoV3" fullword ascii /* score: '4.00'*/
      $s75 = "MMruG'|" fullword ascii /* score: '4.00'*/
      $s76 = "!RYmQXKK" fullword ascii /* score: '4.00'*/
      $s77 = "mKAoja)" fullword ascii /* score: '4.00'*/
      $s78 = ":YFFepIe" fullword ascii /* score: '4.00'*/
      $s79 = "qXScGi:" fullword ascii /* score: '4.00'*/
      $s80 = "XSUgpO<*" fullword ascii /* score: '4.00'*/
      $s81 = "HDPG|31" fullword ascii /* score: '4.00'*/
      $s82 = "qbwNSw~" fullword ascii /* score: '4.00'*/
      $s83 = "-?.sQp" fullword ascii /* score: '4.00'*/
      $s84 = "amWFXY]+G" fullword ascii /* score: '4.00'*/
      $s85 = "rSqEdC=O" fullword ascii /* score: '4.00'*/
      $s86 = "tJINE| " fullword ascii /* score: '4.00'*/
      $s87 = "{CcNy5B7" fullword ascii /* score: '4.00'*/
      $s88 = "D?.oKr" fullword ascii /* score: '4.00'*/
      $s89 = "adym 0lS" fullword ascii /* score: '4.00'*/
      $s90 = "MArqzt'" fullword ascii /* score: '4.00'*/
      $s91 = ".UMF+G" fullword ascii /* score: '4.00'*/
      $s92 = "ZimzJr]M" fullword ascii /* score: '4.00'*/
      $s93 = "nvceymI" fullword ascii /* score: '4.00'*/
      $s94 = "BpzIe\"fH&i" fullword ascii /* score: '4.00'*/
      $s95 = "RBnJ=k5" fullword ascii /* score: '4.00'*/
      $s96 = "SpXZ@h\\" fullword ascii /* score: '4.00'*/
      $s97 = "addb,x<0" fullword ascii /* score: '4.00'*/
      $s98 = "xDyub;c" fullword ascii /* score: '4.00'*/
      $s99 = "CV.9vdTF=%+" fullword ascii /* score: '4.00'*/
      $s100 = "GJjEyCy" fullword ascii /* score: '4.00'*/
      $s101 = "VwSw-8t" fullword ascii /* score: '4.00'*/
      $s102 = "wqsM5A}" fullword ascii /* score: '4.00'*/
      $s103 = "uMvl(S8" fullword ascii /* score: '4.00'*/
      $s104 = "BruC8Q_6" fullword ascii /* score: '4.00'*/
      $s105 = "bLeiUt;" fullword ascii /* score: '4.00'*/
      $s106 = "hrPWN?5" fullword ascii /* score: '4.00'*/
      $s107 = "EeZiYoL*Y" fullword ascii /* score: '4.00'*/
      $s108 = "OoLl_Kr" fullword ascii /* score: '4.00'*/
      $s109 = "v[.Bej" fullword ascii /* score: '4.00'*/
      $s110 = "CwGAY6b" fullword ascii /* score: '4.00'*/
      $s111 = "gnfQ?U" fullword ascii /* score: '4.00'*/
      $s112 = "NquH\\\"" fullword ascii /* score: '4.00'*/
      $s113 = "WBxJYQZ4x" fullword ascii /* score: '4.00'*/
      $s114 = "lHlFkH-" fullword ascii /* score: '4.00'*/
      $s115 = "DUlR\\*" fullword ascii /* score: '4.00'*/
      $s116 = ";xawh0CB" fullword ascii /* score: '4.00'*/
      $s117 = "BZAiCwy@" fullword ascii /* score: '4.00'*/
      $s118 = "FYPxd?" fullword ascii /* score: '4.00'*/
      $s119 = "J`ylUP<Ft" fullword ascii /* score: '4.00'*/
      $s120 = "Ndgl+un" fullword ascii /* score: '4.00'*/
      $s121 = "GyQK{F1=(tW" fullword ascii /* score: '4.00'*/
      $s122 = "PkpZZ~5I" fullword ascii /* score: '4.00'*/
      $s123 = "43vEwfxHtp" fullword ascii /* score: '4.00'*/
      $s124 = "4tSwwGn4" fullword ascii /* score: '4.00'*/
      $s125 = "tXlY'`o/G/," fullword ascii /* score: '4.00'*/
      $s126 = "NCGH^|*+T" fullword ascii /* score: '4.00'*/
      $s127 = "y)!.ndR" fullword ascii /* score: '4.00'*/
      $s128 = "y<?LEsBP+L" fullword ascii /* score: '4.00'*/
      $s129 = "NfIcf. " fullword ascii /* score: '4.00'*/
      $s130 = "TkEIG\"" fullword ascii /* score: '4.00'*/
      $s131 = "OmNZq7z^" fullword ascii /* score: '4.00'*/
      $s132 = "dmLcmb(" fullword ascii /* score: '4.00'*/
      $s133 = "DYQFyi^D" fullword ascii /* score: '4.00'*/
      $s134 = "XfVGcmm" fullword ascii /* score: '4.00'*/
      $s135 = "BrPy@t-" fullword ascii /* score: '4.00'*/
      $s136 = "J+[.nmX" fullword ascii /* score: '4.00'*/
      $s137 = ".rXQ|[0" fullword ascii /* score: '4.00'*/
      $s138 = "kdcB`-`O" fullword ascii /* score: '4.00'*/
      $s139 = "            <!--This Id value indicates the application supports Windows 7/Server 2008 R2 functionality-->" fullword ascii /* score: '3.00'*/
      $s140 = "D$HjDj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s141 = "00(0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s142 = ":<\\u6:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s143 = "SSh`2@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s144 = "33(313F3[3h3p3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s145 = "<At <Bt" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s146 = "            <!--This Id value indicates the application supports Windows 8/Server 2012 functionality-->" fullword ascii /* score: '3.00'*/
      $s147 = "          level=\"asInvoker\"" fullword ascii /* score: '3.00'*/
      $s148 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s149 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii /* score: '2.00'*/
      $s150 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " fullword ascii /* score: '2.00'*/
      $s151 = "TTSi55" fullword ascii /* score: '2.00'*/
      $s152 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s153 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii /* score: '2.00'*/
      $s154 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii /* score: '2.00'*/
      $s155 = "PA<None>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s156 = "    </compatibility>" fullword ascii /* score: '2.00'*/
      $s157 = "5D5S5c5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s158 = "\\!?8_=;" fullword ascii /* score: '2.00'*/
      $s159 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s160 = "\\;%ZNcq" fullword ascii /* score: '2.00'*/
      $s161 = "\\aq,:A" fullword ascii /* score: '2.00'*/
      $s162 = "\\N8CXb" fullword ascii /* score: '2.00'*/
      $s163 = "\\y0e b" fullword ascii /* score: '2.00'*/
      $s164 = "\\b6>tb" fullword ascii /* score: '2.00'*/
      $s165 = "LrmL87" fullword ascii /* score: '2.00'*/
      $s166 = "\\JOq9r" fullword ascii /* score: '2.00'*/
      $s167 = "\\*1>_c" fullword ascii /* score: '2.00'*/
      $s168 = "\\:t[\\>" fullword ascii /* score: '2.00'*/
      $s169 = "\\N8`kx" fullword ascii /* score: '2.00'*/
      $s170 = "vVpDx1" fullword ascii /* score: '2.00'*/
      $s171 = "\\\"~nP@4" fullword ascii /* score: '2.00'*/
      $s172 = "\\Q~\\%z" fullword ascii /* score: '2.00'*/
      $s173 = "\\kFv4ee" fullword ascii /* score: '2.00'*/
      $s174 = "WpNKx6" fullword ascii /* score: '2.00'*/
      $s175 = "\\|7B&P" fullword ascii /* score: '2.00'*/
      $s176 = "\\K{jyN" fullword ascii /* score: '2.00'*/
      $s177 = "\\goka^" fullword ascii /* score: '2.00'*/
      $s178 = "COez12" fullword ascii /* score: '2.00'*/
      $s179 = "\\Da**ku" fullword ascii /* score: '2.00'*/
      $s180 = "\\LdaA\\" fullword ascii /* score: '2.00'*/
      $s181 = "\\9R}>4Q" fullword ascii /* score: '2.00'*/
      $s182 = "0(0K0f0" fullword ascii /* score: '1.00'*/
      $s183 = "gd;-;.*" fullword ascii /* score: '1.00'*/
      $s184 = ":+:1:D:L:" fullword ascii /* score: '1.00'*/
      $s185 = "<.<E<M<V<[<`<v<|<" fullword ascii /* score: '1.00'*/
      $s186 = "a2440225f93a" ascii /* score: '1.00'*/
      $s187 = "q`=H(7'" fullword ascii /* score: '1.00'*/
      $s188 = "3)40494D4`4" fullword ascii /* score: '1.00'*/
      $s189 = ":6:N:S:r:" fullword ascii /* score: '1.00'*/
      $s190 = "=\"=(=2=M={=" fullword ascii /* score: '1.00'*/
      $s191 = "?(?9?H?W?c?y?" fullword ascii /* score: '1.00'*/
      $s192 = "3$303f3r3~3" fullword ascii /* score: '1.00'*/
      $s193 = "8&8,878R8^8|8" fullword ascii /* score: '1.00'*/
      $s194 = "jYW)4XiC" fullword ascii /* score: '1.00'*/
      $s195 = "60L0_0k0r0" fullword ascii /* score: '1.00'*/
      $s196 = "0W0j0p0x0" fullword ascii /* score: '1.00'*/
      $s197 = "6#676>6D6K6P6W6_6d6" fullword ascii /* score: '1.00'*/
      $s198 = "9*:::G:c:l:~:" fullword ascii /* score: '1.00'*/
      $s199 = "; <*<0<6<<<D<J<V<" fullword ascii /* score: '1.00'*/
      $s200 = "6%6J6d6" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806 {
   meta:
      description = "Amadey_MALW - file 2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
   strings:
      $s1 = "za422678.exe" fullword ascii /* score: '19.00'*/
      $s2 = "y11aw21.exe" fullword ascii /* score: '19.00'*/
      $s3 = "1NytCfVRD" fullword ascii /* base64 encoded string '7+B}TC' */ /* score: '14.00'*/
      $s4 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s5 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s6 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s7 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s8 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s9 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s10 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s11 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii /* score: '7.00'*/
      $s12 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii /* score: '7.00'*/
      $s13 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii /* score: '7.00'*/
      $s14 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s15 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s16 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s17 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s18 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s19 = "\\/1m -2/Ef,E" fullword ascii /* score: '6.00'*/
      $s20 = "RSDSwb6" fullword ascii /* score: '5.00'*/
      $s21 = "O -rf&" fullword ascii /* score: '5.00'*/
      $s22 = "vIy]5- " fullword ascii /* score: '5.00'*/
      $s23 = "ffzdbb" fullword ascii /* score: '5.00'*/
      $s24 = "*I- 26" fullword ascii /* score: '5.00'*/
      $s25 = "fTfDD44" fullword ascii /* score: '5.00'*/
      $s26 = "a;Sj+ 5" fullword ascii /* score: '5.00'*/
      $s27 = "O>', -" fullword ascii /* score: '5.00'*/
      $s28 = "TVECvW1" fullword ascii /* score: '5.00'*/
      $s29 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s30 = "Extracting" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 13 times */
      $s31 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s32 = "Extract" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 42 times */
      $s33 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s34 = "PendingFileRenameOperations" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 52 times */
      $s35 = "RegServer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.94'*/ /* Goodware String - occured 57 times */
      $s36 = "Reboot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 105 times */
      $s37 = "SeShutdownPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s38 = "Internet Explorer" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s39 = "=\">>>G>R>Y>p>v>|>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s40 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s41 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s42 = "?+?1?<?B?N?^?g?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s43 = "qxfKApWJR;" fullword ascii /* score: '4.00'*/
      $s44 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s45 = " Qe.hzs{" fullword ascii /* score: '4.00'*/
      $s46 = "?e?q?}?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s47 = ".rdata$brc" fullword ascii /* score: '4.00'*/
      $s48 = "WWj WWWSW" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s49 = "CIdwj,U@-7d" fullword ascii /* score: '4.00'*/
      $s50 = ";#;/;5;<;E;K;S;Y;f;n;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s51 = "11.00.14393.0 (rs1_release.160715-1616)" fullword wide /* score: '4.00'*/
      $s52 = "WEXTRACT.EXE            .MUI" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s53 = "5.IEv," fullword ascii /* score: '4.00'*/
      $s54 = "AhrHKq!Rj" fullword ascii /* score: '4.00'*/
      $s55 = "uuhJK0a" fullword ascii /* score: '4.00'*/
      $s56 = "FsgJ7=." fullword ascii /* score: '4.00'*/
      $s57 = "cTOw]TZ" fullword ascii /* score: '4.00'*/
      $s58 = "ISxq8t@" fullword ascii /* score: '4.00'*/
      $s59 = "kxbkuHZW" fullword ascii /* score: '4.00'*/
      $s60 = "xDQFgSA" fullword ascii /* score: '4.00'*/
      $s61 = "MpXIQsj" fullword ascii /* score: '4.00'*/
      $s62 = "\"?lMBz}h*" fullword ascii /* score: '4.00'*/
      $s63 = "GVPc$:SMXE" fullword ascii /* score: '4.00'*/
      $s64 = "5$BUWuWevfS" fullword ascii /* score: '4.00'*/
      $s65 = "%UrMEcI1" fullword ascii /* score: '4.00'*/
      $s66 = "/%d''d4*Zl-<" fullword ascii /* score: '4.00'*/
      $s67 = "pcSU U7" fullword ascii /* score: '4.00'*/
      $s68 = "gBci\"]" fullword ascii /* score: '4.00'*/
      $s69 = "5vcGqzF8_h9" fullword ascii /* score: '4.00'*/
      $s70 = "aRHrtyf" fullword ascii /* score: '4.00'*/
      $s71 = "lCiC\\k*" fullword ascii /* score: '4.00'*/
      $s72 = "RBDM_qV" fullword ascii /* score: '4.00'*/
      $s73 = "CSiEkoc" fullword ascii /* score: '4.00'*/
      $s74 = "KaTj}tb" fullword ascii /* score: '4.00'*/
      $s75 = "tCRT(.a" fullword ascii /* score: '4.00'*/
      $s76 = ";dGmi?s" fullword ascii /* score: '4.00'*/
      $s77 = "bSDj?sW" fullword ascii /* score: '4.00'*/
      $s78 = "qMNT45A" fullword ascii /* score: '4.00'*/
      $s79 = "axEp!$" fullword ascii /* score: '4.00'*/
      $s80 = "4Z.GWM" fullword ascii /* score: '4.00'*/
      $s81 = "A2-AXecOtK," fullword ascii /* score: '4.00'*/
      $s82 = "NXpw~jN37X" fullword ascii /* score: '4.00'*/
      $s83 = "QwIZp+m" fullword ascii /* score: '4.00'*/
      $s84 = "On.Uet" fullword ascii /* score: '4.00'*/
      $s85 = "DDEE<084" fullword ascii /* score: '4.00'*/
      $s86 = "eEvgDTFD" fullword ascii /* score: '4.00'*/
      $s87 = "LnPV0.E" fullword ascii /* score: '4.00'*/
      $s88 = "QMYUo^X8" fullword ascii /* score: '4.00'*/
      $s89 = "hXGhV\\" fullword ascii /* score: '4.00'*/
      $s90 = "KMmFmeg" fullword ascii /* score: '4.00'*/
      $s91 = "gNSN\"f" fullword ascii /* score: '4.00'*/
      $s92 = "%AtbAk~M" fullword ascii /* score: '4.00'*/
      $s93 = "KeAL,ad" fullword ascii /* score: '4.00'*/
      $s94 = "UEQx*w|z" fullword ascii /* score: '4.00'*/
      $s95 = "AEq;mHkCDtA" fullword ascii /* score: '4.00'*/
      $s96 = "o?pTPV2`a" fullword ascii /* score: '4.00'*/
      $s97 = "ByoM9Cw" fullword ascii /* score: '4.00'*/
      $s98 = "9XIHGEK+" fullword ascii /* score: '4.00'*/
      $s99 = "GRtzTx+K" fullword ascii /* score: '4.00'*/
      $s100 = "UXZX(Xm" fullword ascii /* score: '4.00'*/
      $s101 = "(jhbw?>" fullword ascii /* score: '4.00'*/
      $s102 = "GrLzqN*" fullword ascii /* score: '4.00'*/
      $s103 = "RYjgYpPV#v" fullword ascii /* score: '4.00'*/
      $s104 = "qZJy?IS" fullword ascii /* score: '4.00'*/
      $s105 = "ngjt(u=)" fullword ascii /* score: '4.00'*/
      $s106 = "'ZSkkb'g" fullword ascii /* score: '4.00'*/
      $s107 = "RjJB?j&U" fullword ascii /* score: '4.00'*/
      $s108 = "qTSEL]4" fullword ascii /* score: '4.00'*/
      $s109 = "LtkeF`u" fullword ascii /* score: '4.00'*/
      $s110 = "_WwfyZ]j" fullword ascii /* score: '4.00'*/
      $s111 = "TyBB}WA" fullword ascii /* score: '4.00'*/
      $s112 = "LfznfdxCd" fullword ascii /* score: '4.00'*/
      $s113 = "JAst>u<" fullword ascii /* score: '4.00'*/
      $s114 = "VhWq1su" fullword ascii /* score: '4.00'*/
      $s115 = "?9vctkH\\" fullword ascii /* score: '4.00'*/
      $s116 = "rGGv\"e" fullword ascii /* score: '4.00'*/
      $s117 = "zzgFw4*" fullword ascii /* score: '4.00'*/
      $s118 = "x3+.ebl" fullword ascii /* score: '4.00'*/
      $s119 = "mBhxDe\\" fullword ascii /* score: '4.00'*/
      $s120 = "sEKmq~g" fullword ascii /* score: '4.00'*/
      $s121 = "olSV\"A" fullword ascii /* score: '4.00'*/
      $s122 = "RCKSZE" fullword ascii /* score: '3.50'*/
      $s123 = "ZVJLZW" fullword ascii /* score: '3.50'*/
      $s124 = "OVOQOW" fullword ascii /* score: '3.50'*/
      $s125 = "P>V+]%j;2" fullword ascii /* score: '3.50'*/
      $s126 = "            <!--This Id value indicates the application supports Windows 7/Server 2008 R2 functionality-->" fullword ascii /* score: '3.00'*/
      $s127 = "D$HjDj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s128 = "00(0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s129 = ":<\\u6:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s130 = "SSh`2@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s131 = "33(313F3[3h3p3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s132 = "<At <Bt" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s133 = "            <!--This Id value indicates the application supports Windows 8/Server 2012 functionality-->" fullword ascii /* score: '3.00'*/
      $s134 = "          level=\"asInvoker\"" fullword ascii /* score: '3.00'*/
      $s135 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii /* score: '2.00'*/
      $s136 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " fullword ascii /* score: '2.00'*/
      $s137 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s138 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii /* score: '2.00'*/
      $s139 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii /* score: '2.00'*/
      $s140 = "PA<None>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s141 = "    </compatibility>" fullword ascii /* score: '2.00'*/
      $s142 = "5D5S5c5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s143 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s144 = "JuYUI0" fullword ascii /* score: '2.00'*/
      $s145 = "\\cwp>i}" fullword ascii /* score: '2.00'*/
      $s146 = "\\3SDzph" fullword ascii /* score: '2.00'*/
      $s147 = "\\yxeDK" fullword ascii /* score: '2.00'*/
      $s148 = "\\|c3p_" fullword ascii /* score: '2.00'*/
      $s149 = "\\``;*l" fullword ascii /* score: '2.00'*/
      $s150 = "QqyhR9" fullword ascii /* score: '2.00'*/
      $s151 = "\\F?3{E" fullword ascii /* score: '2.00'*/
      $s152 = "\\pRNr-0" fullword ascii /* score: '2.00'*/
      $s153 = "\\ z^fR" fullword ascii /* score: '2.00'*/
      $s154 = "NHWzr4" fullword ascii /* score: '2.00'*/
      $s155 = "\\ my^X" fullword ascii /* score: '2.00'*/
      $s156 = "\\~-}7t" fullword ascii /* score: '2.00'*/
      $s157 = "cWbSK9" fullword ascii /* score: '2.00'*/
      $s158 = "WeSoP1" fullword ascii /* score: '2.00'*/
      $s159 = "\\[J&z#q" fullword ascii /* score: '2.00'*/
      $s160 = "sJLi06" fullword ascii /* score: '2.00'*/
      $s161 = "\\c)Ial&" fullword ascii /* score: '2.00'*/
      $s162 = "\\4*%uwB" fullword ascii /* score: '2.00'*/
      $s163 = "\\t*TM?" fullword ascii /* score: '2.00'*/
      $s164 = "\\?0x.;" fullword ascii /* score: '2.00'*/
      $s165 = "\\8\"jL9&_" fullword ascii /* score: '2.00'*/
      $s166 = "0(0K0f0" fullword ascii /* score: '1.00'*/
      $s167 = "GmB\"s]" fullword ascii /* score: '1.00'*/
      $s168 = "gd;-;.*" fullword ascii /* score: '1.00'*/
      $s169 = ":+:1:D:L:" fullword ascii /* score: '1.00'*/
      $s170 = "<.<E<M<V<[<`<v<|<" fullword ascii /* score: '1.00'*/
      $s171 = "a2440225f93a" ascii /* score: '1.00'*/
      $s172 = "q`=H(7'" fullword ascii /* score: '1.00'*/
      $s173 = "3)40494D4`4" fullword ascii /* score: '1.00'*/
      $s174 = ":6:N:S:r:" fullword ascii /* score: '1.00'*/
      $s175 = "=\"=(=2=M={=" fullword ascii /* score: '1.00'*/
      $s176 = "?(?9?H?W?c?y?" fullword ascii /* score: '1.00'*/
      $s177 = "3$303f3r3~3" fullword ascii /* score: '1.00'*/
      $s178 = "8&8,878R8^8|8" fullword ascii /* score: '1.00'*/
      $s179 = "60L0_0k0r0" fullword ascii /* score: '1.00'*/
      $s180 = "0W0j0p0x0" fullword ascii /* score: '1.00'*/
      $s181 = "6#676>6D6K6P6W6_6d6" fullword ascii /* score: '1.00'*/
      $s182 = "9*:::G:c:l:~:" fullword ascii /* score: '1.00'*/
      $s183 = "; <*<0<6<<<D<J<V<" fullword ascii /* score: '1.00'*/
      $s184 = "6%6J6d6" fullword ascii /* score: '1.00'*/
      $s185 = "3\\_cKpC" fullword ascii /* score: '1.00'*/
      $s186 = "t3WWh@1@" fullword ascii /* score: '1.00'*/
      $s187 = "3>3]3p3" fullword ascii /* score: '1.00'*/
      $s188 = "jPpI;[" fullword ascii /* score: '1.00'*/
      $s189 = "=2=\\=k=y=" fullword ascii /* score: '1.00'*/
      $s190 = "<9<H<N<W<^<s<" fullword ascii /* score: '1.00'*/
      $s191 = "0,121}1" fullword ascii /* score: '1.00'*/
      $s192 = "<<<`<o<|<" fullword ascii /* score: '1.00'*/
      $s193 = "6595b64144ccf1df" ascii /* score: '1.00'*/
      $s194 = "1'1-13181?1O1Z1`1x1" fullword ascii /* score: '1.00'*/
      $s195 = "lAaH~v" fullword ascii /* score: '1.00'*/
      $s196 = "0$0*030H0N0m0x0" fullword ascii /* score: '1.00'*/
      $s197 = "1.191@1K1]1f1" fullword ascii /* score: '1.00'*/
      $s198 = ">!?(?G?R?g?" fullword ascii /* score: '1.00'*/
      $s199 = "7C8`8l8" fullword ascii /* score: '1.00'*/
      $s200 = ";#;7;@;I;R;q;~;" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_93583dfa872b44e13e449cdfbbe20e64851dbe0e615f30b0313d2cb6a9b2309e {
   meta:
      description = "Amadey_MALW - file 93583dfa872b44e13e449cdfbbe20e64851dbe0e615f30b0313d2cb6a9b2309e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "93583dfa872b44e13e449cdfbbe20e64851dbe0e615f30b0313d2cb6a9b2309e"
   strings:
      $x1 = "DumpTargetConfigurationForLogger" fullword ascii /* score: '32.00'*/
      $x2 = "NLog.Targets.LogReceiverWebServiceTarget, NLog.Wcf" fullword wide /* score: '32.00'*/
      $s3 = "{0}: {1} has been thrown and this is probably due to a race condition.Logging to the console will be paused. Enable by reloading" wide /* score: '30.00'*/
      $s4 = "PNLog.Config.LoggingConfigurationFileLoader+<GetPrivateBinPathNLogLocations>d__14" fullword ascii /* score: '29.00'*/
      $s5 = "NLog.Common.IInternalLoggerContext.get_LogFactory" fullword ascii /* score: '29.00'*/
      $s6 = "TNLog.Config.LoggingConfigurationFileLoader+<GetDefaultCandidateConfigFilePaths>d__11" fullword ascii /* score: '29.00'*/
      $s7 = "MNLog.Config.LoggingConfigurationFileLoader+<GetAppSpecificNLogLocations>d__13" fullword ascii /* score: '29.00'*/
      $s8 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.Add" fullword ascii /* score: '28.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<NLog.Config.LoggingConfigurationParser.ValidatedConfigurationElement>.GetEnumerator" fullword ascii /* score: '27.00'*/
      $s10 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s11 = "yUse LogManager.Setup().LoadConfiguration(c => c.ForLogger(minLevel).WriteTo(target)) instead. Marked obsolete on NLog 5.2" fullword ascii /* score: '27.00'*/
      $s12 = "System.Collections.Generic.IEnumerable<NLog.MessageTemplates.MessageTemplateParameter>.GetEnumerator" fullword ascii /* score: '27.00'*/
      $s13 = "System.Collections.Generic.IEnumerator<NLog.Config.LoggingConfigurationParser.ValidatedConfigurationElement>.get_Current" fullword ascii /* score: '27.00'*/
      $s14 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s15 = "qUse LogManager.Setup().LoadConfiguration(c => c.ForLogger().WriteTo(target)) instead. Marked obsolete on NLog 5.2" fullword ascii /* score: '27.00'*/
      $s16 = "Targets not configured for Logger: {0}" fullword wide /* score: '27.00'*/
      $s17 = "Targets configured when LogLevel >= {0} for Logger: {1}" fullword wide /* score: '27.00'*/
      $s18 = "{0}: File creation time {1} newer than previous file write time {2}. Linux FileSystem probably don't support file birthtime, unl" wide /* score: '26.00'*/
      $s19 = "Failed to create sharable mutex processes" fullword wide /* score: '26.00'*/
      $s20 = "LookupCurrentProcessFilePath Failed - {0}" fullword wide /* score: '26.00'*/
      $s21 = "LookupCurrentProcessFilePath Managed Failed - {0}" fullword wide /* score: '26.00'*/
      $s22 = "LookupCurrentProcessId Failed - {0}" fullword wide /* score: '26.00'*/
      $s23 = "LookupCurrentProcessId Managed Failed - {0}" fullword wide /* score: '26.00'*/
      $s24 = "LookupCurrentProcessName Failed - {0}" fullword wide /* score: '26.00'*/
      $s25 = "LookupCurrentProcessName Managed Failed - {0}" fullword wide /* score: '26.00'*/
      $s26 = "LookupCurrentProcessFilePath Native Failed - {0}" fullword wide /* score: '26.00'*/
      $s27 = "LookupCurrentProcessFilePath Win32 Failed - {0}" fullword wide /* score: '26.00'*/
      $s28 = "LookupCurrentProcessId Native Failed - {0}" fullword wide /* score: '26.00'*/
      $s29 = "LookupCurrentProcessId Win32 Failed - {0}" fullword wide /* score: '26.00'*/
      $s30 = "NLog.Targets.DatabaseTarget, NLog.Database" fullword wide /* score: '26.00'*/
      $s31 = "WebServiceProtocol.Xml requires WebServiceTarget.XmlRoot to be set." fullword wide /* score: '26.00'*/
      $s32 = "System.Collections.Generic.IList<NLog.Targets.Target>.set_Item" fullword ascii /* score: '25.00'*/
      $s33 = "System.Collections.Generic.IEnumerator<NLog.Targets.Target>.get_Current" fullword ascii /* score: '25.00'*/
      $s34 = "System.Collections.Generic.IList<NLog.Targets.Target>.Item" fullword ascii /* score: '25.00'*/
      $s35 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.Clear" fullword ascii /* score: '25.00'*/
      $s36 = "System.Collections.Generic.IList<NLog.Targets.Target>.get_Item" fullword ascii /* score: '25.00'*/
      $s37 = "System.Collections.Generic.IList<NLog.Targets.Target>.Insert" fullword ascii /* score: '25.00'*/
      $s38 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.get_Count" fullword ascii /* score: '25.00'*/
      $s39 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.CopyTo" fullword ascii /* score: '25.00'*/
      $s40 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.Remove" fullword ascii /* score: '25.00'*/
      $s41 = "System.Collections.Generic.IEnumerator<NLog.Targets.Target>.Current" fullword ascii /* score: '25.00'*/
      $s42 = "System.Collections.Generic.IList<NLog.Targets.Target>.IndexOf" fullword ascii /* score: '25.00'*/
      $s43 = "System.Collections.Generic.IList<NLog.Targets.Target>.RemoveAt" fullword ascii /* score: '25.00'*/
      $s44 = "FNLog.Config.AssemblyExtensionLoader+<GetAutoLoadingFileLocations>d__13" fullword ascii /* score: '25.00'*/
      $s45 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.get_IsReadOnly" fullword ascii /* score: '25.00'*/
      $s46 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.Contains" fullword ascii /* score: '25.00'*/
      $s47 = "NLog.Config.IUsesStackTrace.get_StackTraceUsage" fullword ascii /* score: '25.00'*/
      $s48 = "System.Collections.Generic.IEnumerable<NLog.Targets.Target>.GetEnumerator" fullword ascii /* score: '25.00'*/
      $s49 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.IsReadOnly" fullword ascii /* score: '25.00'*/
      $s50 = "System.Collections.Generic.ICollection<NLog.Targets.Target>.Count" fullword ascii /* score: '25.00'*/
      $s51 = "Target flush timeout. One or more targets did not complete flush operation, skipping target close." fullword wide /* score: '25.00'*/
      $s52 = "{0}: Archiving Attempt #{1} to compress {2} to {3} failed - {4} {5}. Sleeping for {6}ms" fullword wide /* score: '25.00'*/
      $s53 = "{0}: Attempt #{1} to open {2} failed - {3} {4}. Sleeping for {5}ms" fullword wide /* score: '25.00'*/
      $s54 = "NLog.Targets.DiagnosticListenerTarget, NLog.DiagnosticSource" fullword wide /* score: '25.00'*/
      $s55 = "NLog.MessageTemplates" fullword ascii /* score: '24.00'*/
      $s56 = "NLog.Common.IInternalLoggerContext.LogFactory" fullword ascii /* score: '24.00'*/
      $s57 = "NLog.ILoggerBase.Log" fullword ascii /* score: '24.00'*/
      $s58 = "]System.Attribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '24.00'*/
      $s59 = "<NLog.SetupLoadConfigurationExtensions+<YieldAllTargets>d__20" fullword ascii /* score: '24.00'*/
      $s60 = "System.Collections.Generic.IEnumerable<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.GetEnumerator" ascii /* score: '23.00'*/
      $s61 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.get_IsReadOnl" ascii /* score: '23.00'*/
      $s62 = "System.Collections.Generic.IEnumerable<NLog.Config.XmlLoggingConfigurationElement>.GetEnumerator" fullword ascii /* score: '23.00'*/
      $s63 = "System.Collections.Generic.IEnumerator<NLog.Config.XmlLoggingConfigurationElement>.get_Current" fullword ascii /* score: '23.00'*/
      $s64 = "\\Instead use ResolveService<IJsonConverter>() in Layout / Target. Marked obsolete on NLog 5.0" fullword ascii /* score: '23.00'*/
      $s65 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.get_IsReadOnl" ascii /* score: '23.00'*/
      $s66 = "ExecuteLogMethod" fullword ascii /* score: '23.00'*/
      $s67 = "Logger: {0} configured with duplicate output to target: {1}. LoggingRule with NamePattern='{2}' and Level={3} has been skipped." fullword wide /* score: '23.00'*/
      $s68 = "^NLog.Targets.MemoryTarget+ThreadSafeList`1+<System-Collections-IEnumerable-GetEnumerator>d__18" fullword ascii /* score: '22.00'*/
      $s69 = "NLog.Targets.FileArchiveModes" fullword ascii /* score: '22.00'*/
      $s70 = "LNLog.Targets.FileArchiveModes.FileArchiveModeBase+<CheckArchiveCleanup>d__16" fullword ascii /* score: '22.00'*/
      $s71 = "System.Collections.Generic.IEnumerator<NLog.Config.LoggingConfigurationParser.ValidatedConfigurationElement>.Current" fullword ascii /* score: '22.00'*/
      $s72 = "GetLoggerThreadSafe" fullword ascii /* score: '22.00'*/
      $s73 = "NNLog.Targets.FileArchiveModes.FileArchiveModeRolling+<CheckArchiveCleanup>d__7" fullword ascii /* score: '22.00'*/
      $s74 = "Jqjfw.exe" fullword wide /* score: '22.00'*/
      $s75 = "?NLog.Targets.MemoryTarget+ThreadSafeList`1+<GetEnumerator>d__13" fullword ascii /* score: '22.00'*/
      $s76 = "LogFactory failed to flush targets." fullword wide /* score: '22.00'*/
      $s77 = "NetworkTarget - Queue Limit ok." fullword wide /* score: '22.00'*/
      $s78 = "NLog.Targets.Wrappers.ImpersonatingTargetWrapper, NLog.WindowsIdentity" fullword wide /* score: '22.00'*/
      $s79 = "NLog.Targets.OutputDebugStringTarget, NLog.OutputDebugString" fullword wide /* score: '22.00'*/
      $s80 = "NLog.Targets.PerformanceCounterTarget, NLog.PerformanceCounter" fullword wide /* score: '22.00'*/
      $s81 = "NLog.Windows.Forms.RichTextBoxTarget, NLog.Windows.Forms" fullword wide /* score: '22.00'*/
      $s82 = "NLog.Windows.Forms.MessageBoxTarget, NLog.Windows.Forms" fullword wide /* score: '22.00'*/
      $s83 = "NLog.Windows.Forms.FormControlTarget, NLog.Windows.Forms" fullword wide /* score: '22.00'*/
      $s84 = "NLog.Windows.Forms.ToolStripItemTarget, NLog.Windows.Forms" fullword wide /* score: '22.00'*/
      $s85 = "KReplaced by StdErr to align with ConsoleTarget. Marked obsolete on NLog 5.0" fullword ascii /* score: '21.00'*/
      $s86 = "ILoggingConfigurationLoader" fullword ascii /* score: '21.00'*/
      $s87 = "LoggingConfigurationFileLoader" fullword ascii /* score: '21.00'*/
      $s88 = "NLog.ILoggerBase.LogException" fullword ascii /* score: '21.00'*/
      $s89 = "LogMessageTemplateFormatter" fullword ascii /* score: '21.00'*/
      $s90 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.Add" fullword ascii /* score: '21.00'*/
      $s91 = "LoggingConfigurationWatchableFileLoader" fullword ascii /* score: '21.00'*/
      $s92 = "NLog.Logger+<Swallow>d__457" fullword ascii /* score: '21.00'*/
      $s93 = "RReplaced by StdErr to align with ColoredConsoleTarget. Marked obsolete on NLog 5.0" fullword ascii /* score: '21.00'*/
      $s94 = "The MailTarget's 'SmtpServer' properties are not set - but needed because useSystemNetMailSettings=false and DeliveryMethod=Netw" wide /* score: '21.00'*/
      $s95 = "The MailTarget's 'PickupDirectoryLocation' properties are not set - but needed because useSystemNetMailSettings=false and Delive" wide /* score: '21.00'*/
      $s96 = "MethodCallTarget: Failed to create expression method {0} - {1}" fullword wide /* score: '21.00'*/
      $s97 = "MethodCallTarget: Failed to invoke reflection method {0} - {1}" fullword wide /* score: '21.00'*/
      $s98 = "FileTarget: parsed date '{0}' from file-template '{1}'" fullword wide /* score: '21.00'*/
      $s99 = "NetworkTarget - Blocking until ready, because queue is full" fullword wide /* score: '21.00'*/
      $s100 = " - Extension NLog.Database not included?" fullword wide /* score: '21.00'*/
      $s101 = "get_CurrentProcessFilePath" fullword ascii /* score: '20.00'*/
      $s102 = "GetFriendlyNameFromProcessName" fullword ascii /* score: '20.00'*/
      $s103 = "get_ArchiveMutex" fullword ascii /* score: '20.00'*/
      $s104 = "GetProcessDir" fullword ascii /* score: '20.00'*/
      $s105 = "NLog.ILogger.Error" fullword ascii /* score: '20.00'*/
      $s106 = "get_UserStackFrameNumberLegacy" fullword ascii /* score: '20.00'*/
      $s107 = "get_ProcessDir" fullword ascii /* score: '20.00'*/
      $s108 = "get_ForceMutexConcurrentWrites" fullword ascii /* score: '20.00'*/
      $s109 = "NLog.Config.ILoggingConfigurationElement.get_Children" fullword ascii /* score: '20.00'*/
      $s110 = "NLog.Config.IUsesStackTrace.StackTraceUsage" fullword ascii /* score: '20.00'*/
      $s111 = "get_SupportsSharableMutex" fullword ascii /* score: '20.00'*/
      $s112 = "NLogMutexTester" fullword wide /* score: '20.00'*/
      $s113 = "NetworkTarget: Error completing network request" fullword wide /* score: '20.00'*/
      $s114 = "NetworkTarget: Error completing failed network request" fullword wide /* score: '20.00'*/
      $s115 = "NetworkTarget: Failed to configure Socket-option {0} = {1}" fullword wide /* score: '20.00'*/
      $s116 = "NetworkTarget: Failed to configure TCP-option {0} = {1}" fullword wide /* score: '20.00'*/
      $s117 = " - Extension NLog.Web not included?" fullword wide /* score: '20.00'*/
      $s118 = "processtime" fullword wide /* score: '19.00'*/
      $s119 = "BReplaced by LogFactory.GetLogger<T>(). Marked obsolete on NLog 5.2" fullword ascii /* score: '19.00'*/
      $s120 = "get_UserTempFilePath" fullword ascii /* score: '19.00'*/
      $s121 = "<GetLogger>b__77_0" fullword ascii /* score: '19.00'*/
      $s122 = "7Replaced by GetLogger<T>(). Marked obsolete on NLog 5.2" fullword ascii /* score: '19.00'*/
      $s123 = "ParseLoggingRuleTargets" fullword ascii /* score: '19.00'*/
      $s124 = "processinfo" fullword wide /* score: '19.00'*/
      $s125 = "eTemporary workaround for broken Layout Renderers that are not threadsafe. Marked obsolete on NLog 5.0" fullword ascii /* score: '19.00'*/
      $s126 = "<GetLogger>b__75_0" fullword ascii /* score: '19.00'*/
      $s127 = "processdir" fullword wide /* score: '19.00'*/
      $s128 = "<GetLogger>b__76_0" fullword ascii /* score: '19.00'*/
      $s129 = "WriteLogEventsToTarget" fullword ascii /* score: '19.00'*/
      $s130 = "&NLog.Targets.TargetPropertyWithContext" fullword ascii /* score: '19.00'*/
      $s131 = "CreateTargetChainFromLoggingRule" fullword ascii /* score: '19.00'*/
      $s132 = "nInstead use LogManager.Setup().SetupExtensions(ext => ext.RegisterTarget<T>()). Marked obsolete with NLog v5.2" fullword ascii /* score: '19.00'*/
      $s133 = "AddTargetsFromLoggingRule" fullword ascii /* score: '19.00'*/
      $s134 = "get_InjectedLanguage" fullword ascii /* score: '19.00'*/
      $s135 = "Missing NLog Target type-alias" fullword wide /* score: '19.00'*/
      $s136 = "Not of type NLog Target" fullword wide /* score: '19.00'*/
      $s137 = "{0}: InitializeTarget is done but not scanned For Layouts" fullword wide /* score: '19.00'*/
      $s138 = "FileTarget FilePathLayout not recognized as absolute path (Maybe change to forward-slash): {0}" fullword wide /* score: '19.00'*/
      $s139 = "{0}: DirectoryNotFoundException - Attempting to create directory for FileName: {1}" fullword wide /* score: '19.00'*/
      $s140 = "NLog.Extensions.Logging.ConfigSettingLayoutRenderer, NLog.Extensions.Logging" fullword wide /* score: '19.00'*/
      $s141 = "TargetNames={0}, ConfigItems={1}" fullword wide /* score: '19.00'*/
      $s142 = "Targets={0}, ConfigItems={1}" fullword wide /* score: '19.00'*/
      $s143 = "Logging rule without name or filter or targets is ignored" fullword wide /* score: '19.00'*/
      $s144 = "{0}: Write operation failed. {1} attempts left. Sleep {2} ms" fullword wide /* score: '19.00'*/
      $s145 = "PARSEMESSAGETEMPLATES" fullword wide /* score: '18.50'*/
      $s146 = " NLog.Logger+<SwallowAsync>d__459" fullword ascii /* score: '18.00'*/
      $s147 = "NLog.Config.INamedItemFactory<TBaseType,System.Type>.CreateInstance" fullword ascii /* score: '18.00'*/
      $s148 = "NLog.Config.INamedItemFactory<TBaseType,System.Type>.TryCreateInstance" fullword ascii /* score: '18.00'*/
      $s149 = "*Trimming - Allow method lookup from config" fullword ascii /* score: '18.00'*/
      $s150 = "<PostPayload>b__0" fullword ascii /* score: '18.00'*/
      $s151 = "NLog.Config.INamedItemFactory<TBaseType,System.Type>.RegisterDefinition" fullword ascii /* score: '18.00'*/
      $s152 = "System.Collections.Generic.IEnumerator<NLog.Config.XmlLoggingConfigurationElement>.Current" fullword ascii /* score: '18.00'*/
      $s153 = "NLog.Config.INamedItemFactory<System.Reflection.MethodInfo,System.Reflection.MethodInfo>.RegisterDefinition" fullword ascii /* score: '18.00'*/
      $s154 = "NLog.Config.INamedItemFactory<System.Reflection.MethodInfo,System.Reflection.MethodInfo>.CreateInstance" fullword ascii /* score: '18.00'*/
      $s155 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.Contains" fullword ascii /* score: '18.00'*/
      $s156 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.CopyTo" fullword ascii /* score: '18.00'*/
      $s157 = "NLog.Config.INamedItemFactory<System.Reflection.MethodInfo,System.Reflection.MethodInfo>.TryCreateInstance" fullword ascii /* score: '18.00'*/
      $s158 = "\"NLog.Logger+<SwallowAsync>d__460`1" fullword ascii /* score: '18.00'*/
      $s159 = "PostPayload" fullword ascii /* score: '18.00'*/
      $s160 = "\"NLog.Logger+<SwallowAsync>d__461`1" fullword ascii /* score: '18.00'*/
      $s161 = " NLog.Logger+<SwallowAsync>d__458" fullword ascii /* score: '18.00'*/
      $s162 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.IsReadOnly" fullword ascii /* score: '18.00'*/
      $s163 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,NLog.Layouts.Layout>>.Remove" fullword ascii /* score: '18.00'*/
      $s164 = "NetworkTarget - Discarding single item, because queue is full" fullword wide /* score: '18.00'*/
      $s165 = "NetworkTarget - Growing the size of queue, because queue is full" fullword wide /* score: '18.00'*/
      $s166 = "NetworkTarget - Entered critical section for queue." fullword wide /* score: '18.00'*/
      $s167 = "{0}: Failed to create global archive mutex: {1}" fullword wide /* score: '18.00'*/
      $s168 = "{0}: Failed to close mutex: '{1}'" fullword wide /* score: '18.00'*/
      $s169 = "NLogPackageLoader contains Preload method" fullword wide /* score: '18.00'*/
      $s170 = "NLogPackageLoader contains a preload method, but isn't static" fullword wide /* score: '18.00'*/
      $s171 = "NLogPackageLoader" fullword wide /* score: '18.00'*/
      $s172 = "JAVASCRIPT" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.50'*/
      $s173 = "INTERNALLOGINCLUDETIMESTAMP" fullword wide /* score: '17.50'*/
      $s174 = "204600704642" ascii /* score: '17.00'*/ /* hex encoded string ' FpFB' */
      $s175 = "wUse LogManager.Setup().LoadConfiguration(c => c.ForLogger().WriteToFile(fileName)) instead. Marked obsolete on NLog 5.2" fullword ascii /* score: '17.00'*/
      $s176 = "NLog.Internal.IStringValueRenderer.GetFormattedString" fullword ascii /* score: '17.00'*/
      $s177 = "NLog.Internal.IRawValue.TryGetRawValue" fullword ascii /* score: '17.00'*/
      $s178 = "2NLog.ScopeContext+<GetAllPropertiesUnwrapped>d__27" fullword ascii /* score: '17.00'*/
      $s179 = "NLog.ILogger.Warn" fullword ascii /* score: '17.00'*/
      $s180 = "NLog.Internal.FileAppenders.ICreateFileParameters.get_FileOpenRetryCount" fullword ascii /* score: '17.00'*/
      $s181 = "compoundTargets" fullword ascii /* score: '17.00'*/
      $s182 = "zUse LogManager.Setup().LoadConfiguration(c => c.ForLogger(minLevel).WriteToConsole()) instead. Marked obsolete on NLog 5.2" fullword ascii /* score: '17.00'*/
      $s183 = "OnLoggerReconfigured" fullword ascii /* score: '17.00'*/
      $s184 = "ParseCompoundTarget" fullword ascii /* score: '17.00'*/
      $s185 = "rUse LogManager.Setup().LoadConfiguration(c => c.ForLogger().WriteToConsole()) instead. Marked obsolete on NLog 5.2" fullword ascii /* score: '17.00'*/
      $s186 = "RemoveTargetThreadSafe" fullword ascii /* score: '17.00'*/
      $s187 = "SmtpPort" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s188 = "NLog.ILogger.Info" fullword ascii /* score: '17.00'*/
      $s189 = "NLog.ILogger.Debug" fullword ascii /* score: '17.00'*/
      $s190 = "HttpPostFormEncodedFormatter" fullword ascii /* score: '17.00'*/
      $s191 = "NLog.Layouts.ITypedLayout.get_ValueType" fullword ascii /* score: '17.00'*/
      $s192 = "AddNewTargetFromConfig" fullword ascii /* score: '17.00'*/
      $s193 = "NLog.ILogger.Trace" fullword ascii /* score: '17.00'*/
      $s194 = "NLog.Internal.FileAppenders.ICreateFileParameters.get_EnableFileDeleteSimpleMonitor" fullword ascii /* score: '17.00'*/
      $s195 = "NLog.Layouts.ITypedLayout.get_InnerLayout" fullword ascii /* score: '17.00'*/
      $s196 = "NLog.ILogger.Fatal" fullword ascii /* score: '17.00'*/
      $s197 = "AddTargetThreadSafe" fullword ascii /* score: '17.00'*/
      $s198 = "BuildLoggerConfiguration" fullword ascii /* score: '17.00'*/
      $s199 = "SetupConfigurationTargetBuilder" fullword ascii /* score: '17.00'*/
      $s200 = "GetLoggingRulesThreadSafe" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule sig_0da5b00e8e941ac4be29830e6040cb5f {
   meta:
      description = "Amadey_MALW - file 0da5b00e8e941ac4be29830e6040cb5f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "6bd20157eb146f12887ccb49fa09ac5b0c817983edc43ca1b665f17ad3ebfb25"
   strings:
      $s1 = "sopeso.exe" fullword ascii /* score: '22.00'*/
      $s2 = "voygcuadage.exe" fullword wide /* score: '22.00'*/
      $s3 = "C:\\tibosewodenak\\loxab\\bidujeguk\\zemiw\\3\\rap\\l.pdb" fullword ascii /* score: '20.00'*/
      $s4 = "FFFFFFFFF4" ascii /* reversed goodware string '4FFFFFFFFF' */ /* score: '15.00'*/
      $s5 = "vvvvvv," fullword ascii /* reversed goodware string ',vvvvvv' */ /* score: '14.00'*/
      $s6 = "Xagurorim zedojokit hikomulaHFal digan covorujiyexabih zetod bahohibinabok xupefamebubu ficexunidayid/Loye warojeguzuco pifayudo" wide /* score: '12.00'*/
      $s7 = "runexobozez" fullword ascii /* score: '11.00'*/
      $s8 = "0Nukipixujabed jova mucater deyon denu jeyacidebo=Rosehozixenemac zikudizufu juxivodasede sogipamoco sijeneluhaBPipubey mofijodi" wide /* score: '10.00'*/
      $s9 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s10 = "@GetVice@0" fullword ascii /* score: '9.00'*/
      $s11 = ";Vewezacuj lorumozila yabo yugigot bocetisezibatin var gemig[Wulitocedala puyinimipotama nozi jeyavo kafigapur nilela dobe jecoh" wide /* score: '9.00'*/
      $s12 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s13 = "bvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s14 = "vvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s15 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s16 = "nvvvvvvvvvvvvvnnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s17 = "kevvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s18 = "vvvvvvvvvvvvvvvvvvg" fullword ascii /* score: '8.00'*/
      $s19 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvs" fullword ascii /* score: '8.00'*/
      $s20 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s21 = "vvvvvvvvvvn" fullword ascii /* score: '8.00'*/
      $s22 = "nvvvvvvvvvvvvvnnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s23 = "vvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s24 = "vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s25 = "nvvvvvvvvvvn" fullword ascii /* score: '8.00'*/
      $s26 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s27 = "rqmnmso" fullword ascii /* score: '8.00'*/
      $s28 = "rinakimuhuzafoluj" fullword ascii /* score: '8.00'*/
      $s29 = "jivuzibibewuyadoruxecidowuguxodolenatumefefirarenolepiwurupuxoyijekoruhe" fullword wide /* score: '8.00'*/
      $s30 = "t:\"D2R2W%)" fullword ascii /* score: '7.00'*/
      $s31 = ".YP:\"h" fullword ascii /* score: '7.00'*/
      $s32 = "ProductVersions" fullword wide /* score: '7.00'*/
      $s33 = "Daporesen cic.Nek hozuheritihos kenelatokupuj jurubenidajiza" fullword wide /* score: '7.00'*/
      $s34 = "Beduyofimux xogozehuyawJNenayebinikove vuhanuzi gariluru jimagig rocesesun jim tedaj mupituhi vuvu+Gejipo puzikaha zuga mesohoyo" wide /* score: '7.00'*/
      $s35 = "FFFFFFFFFFFFFFFFFFF" ascii /* score: '6.50'*/
      $s36 = "1.7.39.44" fullword wide /* score: '6.00'*/
      $s37 = "Budefup" fullword wide /* score: '6.00'*/
      $s38 = "Kenegodiza sikimec covituwutaPPuloperehodop xew pazefom lurefazuyod gesoru gadumolop facelimame lihobiboc tibe#Lovul vefewaripuy" wide /* score: '5.00'*/
      $s39 = "Muxewejakoni/Himekapusacec xumayojub baj curi gofirakokiboluYGafayecixuvux now gulamakavidicu ziyuyedin zunixoregomofa zit laxek" wide /* score: '5.00'*/
      $s40 = "Basiw cujadehocenis" fullword ascii /* score: '4.00'*/
      $s41 = "7\\%S~07" fullword ascii /* score: '4.00'*/
      $s42 = "lvvvvvvvvvvvvvvvvvvvvv;" fullword ascii /* score: '4.00'*/
      $s43 = "Beleboroyere vigasoyuzo jilaw" fullword ascii /* score: '4.00'*/
      $s44 = "URPQQhp`B" fullword ascii /* score: '4.00'*/
      $s45 = "vvvvvvvvvvvvvvvvvvvvvvvvvB" fullword ascii /* score: '4.00'*/
      $s46 = "$ hvvvvvvvvvvvvvvvvvvv2" fullword ascii /* score: '4.00'*/
      $s47 = ".www.&" fullword ascii /* score: '4.00'*/
      $s48 = "uSFvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s49 = "fDeUSc2u" fullword ascii /* score: '4.00'*/
      $s50 = "4SVWh," fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s51 = "(vvvvvvvv" fullword ascii /* score: '4.00'*/
      $s52 = "_Fvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s53 = "hRBbDX-t7%" fullword ascii /* score: '4.00'*/
      $s54 = "IHvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s55 = "WSJx?*" fullword ascii /* score: '4.00'*/
      $s56 = "eeee{{{" fullword ascii /* score: '4.00'*/
      $s57 = "Boruka hipeturuhog" fullword ascii /* score: '4.00'*/
      $s58 = "R0U1vvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s59 = "vvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s60 = "rMlJ16n" fullword ascii /* score: '4.00'*/
      $s61 = "uiVVVVV" fullword ascii /* score: '4.00'*/
      $s62 = "%vvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s63 = "L<W]vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s64 = "vvvvvvvvvvvn{" fullword ascii /* score: '4.00'*/
      $s65 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv-vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s66 = "~8evvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s67 = "vvvvvvvvvvv," fullword ascii /* score: '4.00'*/
      $s68 = "Qr!/{Mvvvvvvvvvvvvvvvvvvvvvvvvvj" fullword ascii /* score: '4.00'*/
      $s69 = "%vvvvvvvvvvvvvvvvvvA" fullword ascii /* score: '4.00'*/
      $s70 = "SJKuOdw*" fullword ascii /* score: '4.00'*/
      $s71 = "Yamohinifo bowi nenukodabebive goyigavu sofusixuyogo" fullword wide /* score: '4.00'*/
      $s72 = "StringFileInform" fullword wide /* score: '4.00'*/
      $s73 = "Copyrighz (C) 2020, wodkagudy" fullword wide /* score: '4.00'*/
      $s74 = "Pucewuhon repisotujoduxoyNJiyipixohorag deceh zoxebej nek fogi nayikux dufa sebumili mugizefilaret wegipJNugakidegamew navisoxud" wide /* score: '4.00'*/
      $s75 = "Wobetesido suvesebuxomelot" fullword wide /* score: '4.00'*/
      $s76 = "Hoxazawiwod fupucu" fullword wide /* score: '4.00'*/
      $s77 = "Moba futumibe(Tanudipa wupavabifinax xemamaweladen marUPofunoc temamojavopu kajenulecola harilupulaz xuyiliso xucutuhabebe yujoy" wide /* score: '4.00'*/
      $s78 = "Bajuhozaximepo nitisi" fullword wide /* score: '4.00'*/
      $s79 = "Hilegehihedo mekanisozu2Likarivasiga wejehumubere huhugoma vijutezumav fav" fullword wide /* score: '4.00'*/
      $s80 = "Bimecefef hefayuguxogesIVeguwakan rojiyutirabila tuxij dexa jehoposabem tijoxexuj vixaxasiju gowe8Rigoniropigox kujakiyasu huba " wide /* score: '4.00'*/
      $s81 = "Ceh kijakadiniradow fafodarix2Zuvemabo dodap cuhuro bahudorebihoke gahodayikukew" fullword wide /* score: '4.00'*/
      $s82 = "8Hofozopuyawa xodolivabic faleki huvidobeyawo kigepirolef" fullword wide /* score: '4.00'*/
      $s83 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s84 = "nvvvvvvvvvv" fullword ascii /* score: '2.00'*/
      $s85 = "\\YUY>eE" fullword ascii /* score: '2.00'*/
      $s86 = "\\!q \\q" fullword ascii /* score: '2.00'*/
      $s87 = "nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '2.00'*/
      $s88 = "vvnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvn" fullword ascii /* score: '2.00'*/
      $s89 = "\\`}o_;" fullword ascii /* score: '2.00'*/
      $s90 = "\\PaEDfQ" fullword ascii /* score: '2.00'*/
      $s91 = "nvvvvvvvvvvv" fullword ascii /* score: '2.00'*/
      $s92 = "k\":)OP" fullword ascii /* score: '1.00'*/
      $s93 = "E`bcs%" fullword ascii /* score: '1.00'*/
      $s94 = "lL-uH " fullword ascii /* score: '1.00'*/
      $s95 = "Bg8>.-" fullword ascii /* score: '1.00'*/
      $s96 = "g2tBivF" fullword ascii /* score: '1.00'*/
      $s97 = "(S)H&&c" fullword ascii /* score: '1.00'*/
      $s98 = "h]Ic}F" fullword ascii /* score: '1.00'*/
      $s99 = "d7z04OO" fullword ascii /* score: '1.00'*/
      $s100 = "e----------------e" fullword ascii /* score: '1.00'*/
      $s101 = "b@X@l\"" fullword ascii /* score: '1.00'*/
      $s102 = "ldo.[%~" fullword ascii /* score: '1.00'*/
      $s103 = "+z^~y6" fullword ascii /* score: '1.00'*/
      $s104 = "t!1FWU" fullword ascii /* score: '1.00'*/
      $s105 = "v+5]Wz" fullword ascii /* score: '1.00'*/
      $s106 = "1X;sK7" fullword ascii /* score: '1.00'*/
      $s107 = "uDVVVV" fullword ascii /* score: '1.00'*/
      $s108 = "sV_|*7" fullword ascii /* score: '1.00'*/
      $s109 = "qeYw[:" fullword ascii /* score: '1.00'*/
      $s110 = "3T ux." fullword ascii /* score: '1.00'*/
      $s111 = "{WDt0>" fullword ascii /* score: '1.00'*/
      $s112 = "DCU`e`&N" fullword ascii /* score: '1.00'*/
      $s113 = "YJzq's" fullword ascii /* score: '1.00'*/
      $s114 = "'jG3${" fullword ascii /* score: '1.00'*/
      $s115 = "u,h\\(@" fullword ascii /* score: '1.00'*/
      $s116 = "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" fullword ascii /* score: '1.00'*/
      $s117 = "krYS;;" fullword ascii /* score: '1.00'*/
      $s118 = "QRl%Us" fullword ascii /* score: '1.00'*/
      $s119 = "]-VNS'" fullword ascii /* score: '1.00'*/
      $s120 = ":%%%%%%%%%%%%" fullword ascii /* score: '1.00'*/
      $s121 = "5omeW~M" fullword ascii /* score: '1.00'*/
      $s122 = "\"2!G\\O." fullword ascii /* score: '1.00'*/
      $s123 = "i=|*e-" fullword ascii /* score: '1.00'*/
      $s124 = "=;tv~Q{" fullword ascii /* score: '1.00'*/
      $s125 = "(qnck,5" fullword ascii /* score: '1.00'*/
      $s126 = "e--------------" fullword ascii /* score: '1.00'*/
      $s127 = "9]m3#Xb" fullword ascii /* score: '1.00'*/
      $s128 = "D8`xhn" fullword ascii /* score: '1.00'*/
      $s129 = "Vq`-=+" fullword ascii /* score: '1.00'*/
      $s130 = "Y0=@q;" fullword ascii /* score: '1.00'*/
      $s131 = "Pq-a@C<" fullword ascii /* score: '1.00'*/
      $s132 = "G%%%%%%%GGGG" fullword ascii /* score: '1.00'*/
      $s133 = "T@l*Qm?" fullword ascii /* score: '1.00'*/
      $s134 = "sy~r:j" fullword ascii /* score: '1.00'*/
      $s135 = "W]blr)|s" fullword ascii /* score: '1.00'*/
      $s136 = "!=2d\"_" fullword ascii /* score: '1.00'*/
      $s137 = "W\"]2T." fullword ascii /* score: '1.00'*/
      $s138 = "uBhi*B" fullword ascii /* score: '1.00'*/
      $s139 = "]9w}#)" fullword ascii /* score: '1.00'*/
      $s140 = "7Rw%a\"" fullword ascii /* score: '1.00'*/
      $s141 = "c$:Fz>~" fullword ascii /* score: '1.00'*/
      $s142 = "1;{cmG\"T&" fullword ascii /* score: '1.00'*/
      $s143 = "r\\(7bs" fullword ascii /* score: '1.00'*/
      $s144 = "E,,,,," fullword ascii /* score: '1.00'*/
      $s145 = "BLA6}tb%" fullword ascii /* score: '1.00'*/
      $s146 = "JK8*DM" fullword ascii /* score: '1.00'*/
      $s147 = "y#4lD#pr" fullword ascii /* score: '1.00'*/
      $s148 = "~^<MKi" fullword ascii /* score: '1.00'*/
      $s149 = "l\" _&z" fullword ascii /* score: '1.00'*/
      $s150 = "<SaIja" fullword ascii /* score: '1.00'*/
      $s151 = "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" ascii /* score: '1.00'*/
      $s152 = " =7*A/" fullword ascii /* score: '1.00'*/
      $s153 = "9YEC8F" fullword ascii /* score: '1.00'*/
      $s154 = "y+oJgqT" fullword ascii /* score: '1.00'*/
      $s155 = "^&224qYy" fullword ascii /* score: '1.00'*/
      $s156 = "Kj4w`b" fullword ascii /* score: '1.00'*/
      $s157 = "/D@yk95" fullword ascii /* score: '1.00'*/
      $s158 = "_NLZ<jN" fullword ascii /* score: '1.00'*/
      $s159 = "K\"`\"m6" fullword ascii /* score: '1.00'*/
      $s160 = "g''''g" fullword ascii /* score: '1.00'*/
      $s161 = "?N-h4W3U" fullword ascii /* score: '1.00'*/
      $s162 = "gq_8?7" fullword ascii /* score: '1.00'*/
      $s163 = "{]VgqW0" fullword ascii /* score: '1.00'*/
      $s164 = "~Kt5{9" fullword ascii /* score: '1.00'*/
      $s165 = "w!S7&s" fullword ascii /* score: '1.00'*/
      $s166 = "pn<OGV" fullword ascii /* score: '1.00'*/
      $s167 = "iy5+(:" fullword ascii /* score: '1.00'*/
      $s168 = "^YR$-&0" fullword ascii /* score: '1.00'*/
      $s169 = "gW*!\"Ak" fullword ascii /* score: '1.00'*/
      $s170 = "4N4c-S" fullword ascii /* score: '1.00'*/
      $s171 = "|%c+m\\e" fullword ascii /* score: '1.00'*/
      $s172 = "9Ds%xB" fullword ascii /* score: '1.00'*/
      $s173 = "#Oq}3F?" fullword ascii /* score: '1.00'*/
      $s174 = "r[]!EN" fullword ascii /* score: '1.00'*/
      $s175 = "qV~'5&" fullword ascii /* score: '1.00'*/
      $s176 = "a.%%%%%%%%%%%%%%%%%%%" fullword ascii /* score: '1.00'*/
      $s177 = "8yo^P*2" fullword ascii /* score: '1.00'*/
      $s178 = "72jHIa=" fullword ascii /* score: '1.00'*/
      $s179 = "_NV,~E9V" fullword ascii /* score: '1.00'*/
      $s180 = "T@xwGt" fullword ascii /* score: '1.00'*/
      $s181 = "^_G)4QKh" fullword ascii /* score: '1.00'*/
      $s182 = ">^R8B:f&=" fullword ascii /* score: '1.00'*/
      $s183 = "[07O7?" fullword ascii /* score: '1.00'*/
      $s184 = "\"3(;KS" fullword ascii /* score: '1.00'*/
      $s185 = "Mzj6Q7" fullword ascii /* score: '1.00'*/
      $s186 = "kHTRQi" fullword ascii /* score: '1.00'*/
      $s187 = "G0BI;T" fullword ascii /* score: '1.00'*/
      $s188 = "D=yAs`" fullword ascii /* score: '1.00'*/
      $s189 = "!2b;!r" fullword ascii /* score: '1.00'*/
      $s190 = "Gy6uY!q" fullword ascii /* score: '1.00'*/
      $s191 = "%%%%%%%%gr" fullword ascii /* score: '1.00'*/
      $s192 = "y=d;d!C" fullword ascii /* score: '1.00'*/
      $s193 = "^h,g}V" fullword ascii /* score: '1.00'*/
      $s194 = "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" ascii /* score: '1.00'*/
      $s195 = "tWy^z+" fullword ascii /* score: '1.00'*/
      $s196 = "h:v3fM@:" fullword ascii /* score: '1.00'*/
      $s197 = ">ZKM=x" fullword ascii /* score: '1.00'*/
      $s198 = ";>k5]<" fullword ascii /* score: '1.00'*/
      $s199 = "HGd1*1xL" fullword ascii /* score: '1.00'*/
      $s200 = "<}WG3U" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule cc5e48eb9cf7308dedf57d5e468e836f {
   meta:
      description = "Amadey_MALW - file cc5e48eb9cf7308dedf57d5e468e836f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "8babde64a6d3b85c2c4315205ae58884ee01f6364477a777f09d5b9c3ceef2a6"
   strings:
      $s1 = "fijacukiri.exe" fullword ascii /* score: '22.00'*/
      $s2 = "voygcuadoge.exe" fullword wide /* score: '22.00'*/
      $s3 = "C:\\horonu\\suyi\\xapum_foyozunehax-tubak80\\xo.pdb" fullword ascii /* score: '20.00'*/
      $s4 = "Xagurorim zedojokit hikomulaHFal digan covorujiyexabih zetod bahohibinabok xupefamebubu ficexunidayid/Loye warojeguzuco pifayudo" wide /* score: '12.00'*/
      $s5 = "Daporesen cic.Nek hozuheritihos kenelatokupuj jurubenidajiza+Mevu zigu rubacoluye jipebe ciheyevasetotot" fullword wide /* score: '12.00'*/
      $s6 = "0Nukipixujabed jova mucater deyon denu jeyacidebo=Rosehozixenemac zikudizufu juxivodasede sogipamoco sijeneluhaBPipubey mofijodi" wide /* score: '10.00'*/
      $s7 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s8 = "@GetVice@0" fullword ascii /* score: '9.00'*/
      $s9 = ";Vewezacuj lorumozila yabo yugigot bocetisezibatin var gemig[Wulitocedala puyinimipotama nozi jeyavo kafigapur nilela dobe jecoh" wide /* score: '9.00'*/
      $s10 = "@GetFirstVice@0" fullword ascii /* score: '9.00'*/
      $s11 = "Tiholavogi babacose jeyevaxpewune romipereveju" fullword ascii /* score: '9.00'*/
      $s12 = "bvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s13 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s14 = "vvvvvvvvvvvvvvvvvvg" fullword ascii /* score: '8.00'*/
      $s15 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvs" fullword ascii /* score: '8.00'*/
      $s16 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s17 = "vvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s18 = "vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s19 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s20 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s21 = "vvvvvvvn" fullword ascii /* score: '8.00'*/
      $s22 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s23 = "Diyatekedame movugomikilihar sexecama" fullword wide /* score: '8.00'*/
      $s24 = "budesorozefabijicu" fullword wide /* score: '8.00'*/
      $s25 = "ProductVersions" fullword wide /* score: '7.00'*/
      $s26 = "Beduyofimux xogozehuyawJNenayebinikove vuhanuzi gariluru jimagig rocesesun jim tedaj mupituhi vuvu+Gejipo puzikaha zuga mesohoyo" wide /* score: '7.00'*/
      $s27 = "Budefup" fullword wide /* score: '6.00'*/
      $s28 = "Ovvvvvvvvvvvvvv" fullword ascii /* score: '6.00'*/
      $s29 = "Megotuzoteneri" fullword ascii /* score: '6.00'*/
      $s30 = "bukesubozudewivofa rogovuxakobigoyozevoxuz nudiziwimojurar kamuzupenoh niyici" fullword ascii /* score: '6.00'*/
      $s31 = "Tvvvvvvvvvvvv" fullword ascii /* score: '6.00'*/
      $s32 = "1.7.39.28" fullword wide /* score: '6.00'*/
      $s33 = "XGuci sevuborigili poxocakef gawituvico dadukolan soviwavitafec tuhonol liyo zilameluxaruZVujun lavicomepit xavedoboxum tinuvovu" wide /* score: '6.00'*/
      $s34 = "PPuloperehodop xew pazefom lurefazuyod gesoru gadumolop facelimame lihobiboc tibe#Lovul vefewaripuyuw yofozivo lufugiBLako hifil" wide /* score: '5.00'*/
      $s35 = "jSicovogapetopo dupesejofijeju vufazahekov getedaw bayoce yisefacahosipi juvepuderoya tan yuzekihile sutozu2Vucisid jinejifonivi" wide /* score: '5.00'*/
      $s36 = "Basiw cujadehocenis" fullword ascii /* score: '4.00'*/
      $s37 = "lvvvvvvvvvvvvvvvvvvvvv;" fullword ascii /* score: '4.00'*/
      $s38 = "vvvvvvvvvvvvvvvvvvvvvvvvvB" fullword ascii /* score: '4.00'*/
      $s39 = "$ hvvvvvvvvvvvvvvvvvvv2" fullword ascii /* score: '4.00'*/
      $s40 = "uSFvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s41 = "_Fvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s42 = "IHvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s43 = "R0U1vvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s44 = "vvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s45 = "L<W]vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s46 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv-vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s47 = "~8evvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s48 = "Qr!/{Mvvvvvvvvvvvvvvvvvvvvvvvvvj" fullword ascii /* score: '4.00'*/
      $s49 = "%vvvvvvvvvvvvvvvvvvA" fullword ascii /* score: '4.00'*/
      $s50 = "Yamohinifo bowi nenukodabebive goyigavu sofusixuyogo" fullword wide /* score: '4.00'*/
      $s51 = "StringFileInform" fullword wide /* score: '4.00'*/
      $s52 = "Copyrighz (C) 2020, wodkagudy" fullword wide /* score: '4.00'*/
      $s53 = "Wobetesido suvesebuxomelot" fullword wide /* score: '4.00'*/
      $s54 = "Moba futumibe(Tanudipa wupavabifinax xemamaweladen marUPofunoc temamojavopu kajenulecola harilupulaz xuyiliso xucutuhabebe yujoy" wide /* score: '4.00'*/
      $s55 = "Hilegehihedo mekanisozu2Likarivasiga wejehumubere huhugoma vijutezumav fav" fullword wide /* score: '4.00'*/
      $s56 = "Ceh kijakadiniradow fafodarix2Zuvemabo dodap cuhuro bahudorebihoke gahodayikukew" fullword wide /* score: '4.00'*/
      $s57 = "jEWPj]t" fullword ascii /* score: '4.00'*/
      $s58 = "WULT`lF" fullword ascii /* score: '4.00'*/
      $s59 = "LeeQeg]" fullword ascii /* score: '4.00'*/
      $s60 = "zqBR\\3" fullword ascii /* score: '4.00'*/
      $s61 = "K[vvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s62 = "r,vvvvvvvv" fullword ascii /* score: '4.00'*/
      $s63 = "nvvvvvvvvvvv,{" fullword ascii /* score: '4.00'*/
      $s64 = ".PLU-rk" fullword ascii /* score: '4.00'*/
      $s65 = "YQKS>}]" fullword ascii /* score: '4.00'*/
      $s66 = "vvvvvvvvvvvvvvvvvvvU" fullword ascii /* score: '4.00'*/
      $s67 = "BunbLt'" fullword ascii /* score: '4.00'*/
      $s68 = "fnevTGR" fullword ascii /* score: '4.00'*/
      $s69 = "wHExuaG" fullword ascii /* score: '4.00'*/
      $s70 = "mWHWqJr" fullword ascii /* score: '4.00'*/
      $s71 = "vvvvvvvvvvvvvvT" fullword ascii /* score: '4.00'*/
      $s72 = "URPQQhPrB" fullword ascii /* score: '4.00'*/
      $s73 = "GZKC;1m" fullword ascii /* score: '4.00'*/
      $s74 = "UrHWXKXx" fullword ascii /* score: '4.00'*/
      $s75 = "Z %S?Nh;" fullword ascii /* score: '4.00'*/
      $s76 = "vvvvvvvvvvvvvvvvvvvvvO[U[IT" fullword ascii /* score: '4.00'*/
      $s77 = "lZFu1/," fullword ascii /* score: '4.00'*/
      $s78 = "i5cRwAv,s]" fullword ascii /* score: '4.00'*/
      $s79 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvnvvvvvvvvvvvvvvvvvvv;" fullword ascii /* score: '4.00'*/
      $s80 = "vvvvvvvvvvvvvvvvvUaw_7" fullword ascii /* score: '4.00'*/
      $s81 = "Hofebohar kuba gozohodoro birob" fullword ascii /* score: '4.00'*/
      $s82 = "vvvvvvvvvvvvvvvvv[" fullword ascii /* score: '4.00'*/
      $s83 = "wdxHt!" fullword ascii /* score: '4.00'*/
      $s84 = "rjtw]2lBd" fullword ascii /* score: '4.00'*/
      $s85 = "DgvYBvDFP~$" fullword ascii /* score: '4.00'*/
      $s86 = "odrwkL," fullword ascii /* score: '4.00'*/
      $s87 = ">OJSRfwta" fullword ascii /* score: '4.00'*/
      $s88 = "Jab sofbisyfviudc" fullword ascii /* score: '4.00'*/
      $s89 = "vvvvvvvvvvvvvvvvvF" fullword ascii /* score: '4.00'*/
      $s90 = "{vvvvvvv" fullword ascii /* score: '4.00'*/
      $s91 = "Roresijeciy loperev soligo sejih" fullword ascii /* score: '4.00'*/
      $s92 = "kojizarowicamupu" fullword wide /* score: '4.00'*/
      $s93 = "Dedelawubuxu hopij sayubuxusahexa" fullword wide /* score: '4.00'*/
      $s94 = "NJiyipixohorag deceh zoxebej nek fogi nayikux dufa sebumili mugizefilaret wegipJNugakidegamew navisoxud mamazoxe nipehaga jahuy " wide /* score: '4.00'*/
      $s95 = "IVeguwakan rojiyutirabila tuxij dexa jehoposabem tijoxexuj vixaxasiju gowe8Rigoniropigox kujakiyasu huba mihogeman devehahizeze " wide /* score: '4.00'*/
      $s96 = ":Fiparavahi digopeziluvanes zeho sas xozaxu docefamuxesizonlRigusajavazin cilulekupaka hodolo dikuzefuhivowa huzagagigaxetap nub" wide /* score: '4.00'*/
      $s97 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s98 = "\\=sl21" fullword ascii /* score: '2.00'*/
      $s99 = "OPtq86" fullword ascii /* score: '2.00'*/
      $s100 = "JNrY45" fullword ascii /* score: '2.00'*/
      $s101 = "pdX118" fullword ascii /* score: '2.00'*/
      $s102 = "xJGo56" fullword ascii /* score: '2.00'*/
      $s103 = "D8`xhn" fullword ascii /* score: '1.00'*/
      $s104 = "/D@yk95" fullword ascii /* score: '1.00'*/
      $s105 = "HGd1*1xL" fullword ascii /* score: '1.00'*/
      $s106 = "%s %f %c" fullword ascii /* score: '1.00'*/
      $s107 = "!Sbs;-0" fullword ascii /* score: '1.00'*/
      $s108 = "Yav fug" fullword ascii /* score: '1.00'*/
      $s109 = "QLso>8" fullword ascii /* score: '1.00'*/
      $s110 = "-IQhE&&" fullword ascii /* score: '1.00'*/
      $s111 = "1.16.46" fullword wide /* score: '1.00'*/
      $s112 = "E@XjdB" fullword ascii /* score: '1.00'*/
      $s113 = "6G]@+J9" fullword ascii /* score: '1.00'*/
      $s114 = "~t'|Up<lEQ" fullword ascii /* score: '1.00'*/
      $s115 = "@,p.T," fullword ascii /* score: '1.00'*/
      $s116 = "OXz8P~" fullword ascii /* score: '1.00'*/
      $s117 = "(ayc^Tu" fullword ascii /* score: '1.00'*/
      $s118 = "ynSyBg" fullword ascii /* score: '1.00'*/
      $s119 = "@odyI.0" fullword ascii /* score: '1.00'*/
      $s120 = "'!rDpUh" fullword ascii /* score: '1.00'*/
      $s121 = "|g24:2" fullword ascii /* score: '1.00'*/
      $s122 = "{Prvx3" fullword ascii /* score: '1.00'*/
      $s123 = "V3}I!`cL" fullword ascii /* score: '1.00'*/
      $s124 = "!xc&T~" fullword ascii /* score: '1.00'*/
      $s125 = "b9>b!)H" fullword ascii /* score: '1.00'*/
      $s126 = "z_[kY+b" fullword ascii /* score: '1.00'*/
      $s127 = "l/=CLd" fullword ascii /* score: '1.00'*/
      $s128 = "WC_PsQ|" fullword ascii /* score: '1.00'*/
      $s129 = "5KKx\\v" fullword ascii /* score: '1.00'*/
      $s130 = "{6vptC=" fullword ascii /* score: '1.00'*/
      $s131 = "R 7Ip[" fullword ascii /* score: '1.00'*/
      $s132 = "cfCI5a" fullword ascii /* score: '1.00'*/
      $s133 = "1nndhB" fullword ascii /* score: '1.00'*/
      $s134 = "}TBn2;kl" fullword ascii /* score: '1.00'*/
      $s135 = "^Z$,m':1" fullword ascii /* score: '1.00'*/
      $s136 = "!\"[&~$" fullword ascii /* score: '1.00'*/
      $s137 = "M9a;F2" fullword ascii /* score: '1.00'*/
      $s138 = "IXQGw>" fullword ascii /* score: '1.00'*/
      $s139 = "@b,Zk{" fullword ascii /* score: '1.00'*/
      $s140 = "j)C)L.J" fullword ascii /* score: '1.00'*/
      $s141 = "q J|\\w8" fullword ascii /* score: '1.00'*/
      $s142 = "+cmm!z0" fullword ascii /* score: '1.00'*/
      $s143 = "$xC#FsA" fullword ascii /* score: '1.00'*/
      $s144 = "mk#Q{=fy4" fullword ascii /* score: '1.00'*/
      $s145 = "sEB/7K=He" fullword ascii /* score: '1.00'*/
      $s146 = "|*u8KF{" fullword ascii /* score: '1.00'*/
      $s147 = "v#]gNX" fullword ascii /* score: '1.00'*/
      $s148 = "D;MH/'" fullword ascii /* score: '1.00'*/
      $s149 = "x;ERL." fullword ascii /* score: '1.00'*/
      $s150 = "B{X:+G^" fullword ascii /* score: '1.00'*/
      $s151 = "?6I:!$" fullword ascii /* score: '1.00'*/
      $s152 = "2YCNrX" fullword ascii /* score: '1.00'*/
      $s153 = "M$'](<d" fullword ascii /* score: '1.00'*/
      $s154 = "V$-=La%" fullword ascii /* score: '1.00'*/
      $s155 = "}L3:9~c&8" fullword ascii /* score: '1.00'*/
      $s156 = "!=rO7C" fullword ascii /* score: '1.00'*/
      $s157 = "9p*zRWuK" fullword ascii /* score: '1.00'*/
      $s158 = ">;j:X93" fullword ascii /* score: '1.00'*/
      $s159 = "L\\`|P(-" fullword ascii /* score: '1.00'*/
      $s160 = ";iq)$z" fullword ascii /* score: '1.00'*/
      $s161 = "weyZAw" fullword ascii /* score: '1.00'*/
      $s162 = "[S(DD~" fullword ascii /* score: '1.00'*/
      $s163 = "&o~$_Y" fullword ascii /* score: '1.00'*/
      $s164 = "U8^7*1" fullword ascii /* score: '1.00'*/
      $s165 = "ITR-@Y" fullword ascii /* score: '1.00'*/
      $s166 = "|80s.d" fullword ascii /* score: '1.00'*/
      $s167 = "6vEB(0V" fullword ascii /* score: '1.00'*/
      $s168 = "ZgE5tj" fullword ascii /* score: '1.00'*/
      $s169 = "!AMo-K8{" fullword ascii /* score: '1.00'*/
      $s170 = "41{5Dy" fullword ascii /* score: '1.00'*/
      $s171 = "Gh#+aD" fullword ascii /* score: '1.00'*/
      $s172 = "I48gTC" fullword ascii /* score: '1.00'*/
      $s173 = "-dd%%U" fullword ascii /* score: '1.00'*/
      $s174 = "2c}aa6c#" fullword ascii /* score: '1.00'*/
      $s175 = "U)$2quz" fullword ascii /* score: '1.00'*/
      $s176 = "$H<Rl|{n" fullword ascii /* score: '1.00'*/
      $s177 = "c3T{_F'" fullword ascii /* score: '1.00'*/
      $s178 = "U7qtWn" fullword ascii /* score: '1.00'*/
      $s179 = "VI`U^j" fullword ascii /* score: '1.00'*/
      $s180 = "L}j6hk" fullword ascii /* score: '1.00'*/
      $s181 = ">MWFoS" fullword ascii /* score: '1.00'*/
      $s182 = "6ZmG`a" fullword ascii /* score: '1.00'*/
      $s183 = "RZ]00`$" fullword ascii /* score: '1.00'*/
      $s184 = "Td;&:<" fullword ascii /* score: '1.00'*/
      $s185 = "80Dh%,@" fullword ascii /* score: '1.00'*/
      $s186 = "{#>GJsA$" fullword ascii /* score: '1.00'*/
      $s187 = "9ij6*hC" fullword ascii /* score: '1.00'*/
      $s188 = "+bh] #" fullword ascii /* score: '1.00'*/
      $s189 = "Tz#C9fy" fullword ascii /* score: '1.00'*/
      $s190 = "vvvvvvvvvvvvvv" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s191 = "/^zm-P" fullword ascii /* score: '1.00'*/
      $s192 = ";NxrGc." fullword ascii /* score: '1.00'*/
      $s193 = "&Q\\RN5" fullword ascii /* score: '1.00'*/
      $s194 = "<j](Gj" fullword ascii /* score: '1.00'*/
      $s195 = "d@M:2j" fullword ascii /* score: '1.00'*/
      $s196 = "IAT[;D" fullword ascii /* score: '1.00'*/
      $s197 = "Q>jDEE" fullword ascii /* score: '1.00'*/
      $s198 = "c;b`5_" fullword ascii /* score: '1.00'*/
      $s199 = "e|x,7o" fullword ascii /* score: '1.00'*/
      $s200 = "Ad+KMs" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_142cbad8b9d400380c78935e60db104ec080812b1a298f9753a41b2811c856be {
   meta:
      description = "Amadey_MALW - file 142cbad8b9d400380c78935e60db104ec080812b1a298f9753a41b2811c856be"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "142cbad8b9d400380c78935e60db104ec080812b1a298f9753a41b2811c856be"
   strings:
      $s1 = "customXml/itemProps2.xml" fullword ascii /* score: '14.00'*/
      $s2 = "customXml/itemProps1.xml" fullword ascii /* score: '14.00'*/
      $s3 = "customXml/itemProps3.xmlPK" fullword ascii /* score: '11.00'*/
      $s4 = "customXml/itemProps1.xmlPK" fullword ascii /* score: '11.00'*/
      $s5 = "customXml/itemProps3.xmle" fullword ascii /* score: '11.00'*/
      $s6 = "customXml/itemProps2.xmlPK" fullword ascii /* score: '11.00'*/
      $s7 = "docProps/core.xml" fullword ascii /* score: '7.00'*/
      $s8 = "customXml/_rels/item3.xml.relsPK" fullword ascii /* score: '7.00'*/
      $s9 = "customXml/_rels/item1.xml.rels" fullword ascii /* score: '7.00'*/
      $s10 = "docProps/app.xml" fullword ascii /* score: '7.00'*/
      $s11 = "word/_rels/settings.xml.rels" fullword ascii /* score: '7.00'*/
      $s12 = "customXml/item1.xml" fullword ascii /* score: '7.00'*/
      $s13 = "customXml/item2.xml" fullword ascii /* score: '7.00'*/
      $s14 = "customXml/_rels/item1.xml.relsPK" fullword ascii /* score: '7.00'*/
      $s15 = "word/_rels/settings.xml.relsPK" fullword ascii /* score: '7.00'*/
      $s16 = "customXml/_rels/item2.xml.relsPK" fullword ascii /* score: '7.00'*/
      $s17 = "customXml/_rels/item3.xml.rels" fullword ascii /* score: '7.00'*/
      $s18 = "customXml/_rels/item2.xml.rels" fullword ascii /* score: '7.00'*/
      $s19 = "docProps/custom.xml" fullword ascii /* score: '7.00'*/
      $s20 = "customXml/item2.xmlPK" fullword ascii /* score: '4.00'*/
      $s21 = "customXml/item1.xmlPK" fullword ascii /* score: '4.00'*/
      $s22 = "?g2%d3" fullword ascii /* score: '4.00'*/
      $s23 = "THNIbeQ" fullword ascii /* score: '4.00'*/
      $s24 = "@`PdTtLl\\|BbZzFfVvNn^IiYyE" fullword ascii /* score: '4.00'*/
      $s25 = "jWlqKee|" fullword ascii /* score: '4.00'*/
      $s26 = "'UHXd9H4," fullword ascii /* score: '4.00'*/
      $s27 = "lzpe\"^s" fullword ascii /* score: '4.00'*/
      $s28 = "docProps/custom.xmlPK" fullword ascii /* score: '4.00'*/
      $s29 = "rEQC5Q?" fullword ascii /* score: '4.00'*/
      $s30 = "customXml/item3.xmlPK" fullword ascii /* score: '4.00'*/
      $s31 = "DQgIK}O" fullword ascii /* score: '4.00'*/
      $s32 = "hjdo?in" fullword ascii /* score: '4.00'*/
      $s33 = "word/media/image1.jpeg" fullword ascii /* score: '4.00'*/
      $s34 = "DEAEz'*" fullword ascii /* score: '4.00'*/
      $s35 = ")euUU/G~q" fullword ascii /* score: '4.00'*/
      $s36 = "customXml/item3.xmlm" fullword ascii /* score: '4.00'*/
      $s37 = "WbbakJ!" fullword ascii /* score: '4.00'*/
      $s38 = "word/media/image1.jpegPK" fullword ascii /* score: '4.00'*/
      $s39 = " iu(PvIVHUm" fullword ascii /* score: '4.00'*/
      $s40 = "zSFC|[~r" fullword ascii /* score: '4.00'*/
      $s41 = "word/numbering.xmlPK" fullword ascii /* score: '4.00'*/
      $s42 = "kzMNJ~\"" fullword ascii /* score: '4.00'*/
      $s43 = "word/_rels/document.xml.rels" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s44 = "word/numbering.xml" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s45 = "word/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s46 = "word/webSettings.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s47 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s48 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s49 = "word/fontTable.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s50 = "\\~L-qzQ;[s`" fullword ascii /* score: '2.00'*/
      $s51 = "\\uEy&;I" fullword ascii /* score: '2.00'*/
      $s52 = "\\M!^t76" fullword ascii /* score: '2.00'*/
      $s53 = "guzsL8" fullword ascii /* score: '2.00'*/
      $s54 = "word/document.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s55 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s56 = "word/settings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s57 = "word/webSettings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s58 = "G=^TAh4" fullword ascii /* score: '1.00'*/
      $s59 = "R]@WaU" fullword ascii /* score: '1.00'*/
      $s60 = ";:|fZD" fullword ascii /* score: '1.00'*/
      $s61 = "+ZZ<#0X" fullword ascii /* score: '1.00'*/
      $s62 = "c-{<24" fullword ascii /* score: '1.00'*/
      $s63 = "={dLoh," fullword ascii /* score: '1.00'*/
      $s64 = "s!H Gx" fullword ascii /* score: '1.00'*/
      $s65 = "-(3i@ZP" fullword ascii /* score: '1.00'*/
      $s66 = "hC,x4L>" fullword ascii /* score: '1.00'*/
      $s67 = "*V3x6\\/" fullword ascii /* score: '1.00'*/
      $s68 = "1TBj#;" fullword ascii /* score: '1.00'*/
      $s69 = "{\"j~?j9" fullword ascii /* score: '1.00'*/
      $s70 = "[kfKa#" fullword ascii /* score: '1.00'*/
      $s71 = "o=#[\\VP" fullword ascii /* score: '1.00'*/
      $s72 = "~o|#FE" fullword ascii /* score: '1.00'*/
      $s73 = "VxD{58" fullword ascii /* score: '1.00'*/
      $s74 = "g~~6Ua<w{" fullword ascii /* score: '1.00'*/
      $s75 = "A9:{BP" fullword ascii /* score: '1.00'*/
      $s76 = "R_T!^Xu" fullword ascii /* score: '1.00'*/
      $s77 = "6{=XwG[" fullword ascii /* score: '1.00'*/
      $s78 = ":F@|47" fullword ascii /* score: '1.00'*/
      $s79 = "ZW#5$2" fullword ascii /* score: '1.00'*/
      $s80 = "b]O(-)" fullword ascii /* score: '1.00'*/
      $s81 = "V8^Q@." fullword ascii /* score: '1.00'*/
      $s82 = "E\"4qi<d" fullword ascii /* score: '1.00'*/
      $s83 = "Ytz*@N{" fullword ascii /* score: '1.00'*/
      $s84 = "!Ru A)" fullword ascii /* score: '1.00'*/
      $s85 = "eV-VTp" fullword ascii /* score: '1.00'*/
      $s86 = ")9|lNxt" fullword ascii /* score: '1.00'*/
      $s87 = "QD6?G2" fullword ascii /* score: '1.00'*/
      $s88 = "d[3!51" fullword ascii /* score: '1.00'*/
      $s89 = "oU*Ytgs" fullword ascii /* score: '1.00'*/
      $s90 = "}#]NT3" fullword ascii /* score: '1.00'*/
      $s91 = "D9XLbT" fullword ascii /* score: '1.00'*/
      $s92 = ")Zq0S{" fullword ascii /* score: '1.00'*/
      $s93 = "JzTyG;" fullword ascii /* score: '1.00'*/
      $s94 = "A|\"j'N" fullword ascii /* score: '1.00'*/
      $s95 = "_~Ov#N" fullword ascii /* score: '1.00'*/
      $s96 = "Z\"fff3" fullword ascii /* score: '1.00'*/
      $s97 = "kjeY(]" fullword ascii /* score: '1.00'*/
      $s98 = ",ust>W" fullword ascii /* score: '1.00'*/
      $s99 = "%c0>h5" fullword ascii /* score: '1.00'*/
      $s100 = "j{Po3q3" fullword ascii /* score: '1.00'*/
      $s101 = "o_d >D_z" fullword ascii /* score: '1.00'*/
      $s102 = "]z<3rdI" fullword ascii /* score: '1.00'*/
      $s103 = "j9'{Pm" fullword ascii /* score: '1.00'*/
      $s104 = "==^sF@" fullword ascii /* score: '1.00'*/
      $s105 = "5.):)@" fullword ascii /* score: '1.00'*/
      $s106 = "'uC<Dd" fullword ascii /* score: '1.00'*/
      $s107 = "{pb8 ZqO" fullword ascii /* score: '1.00'*/
      $s108 = "T=~'e|" fullword ascii /* score: '1.00'*/
      $s109 = "$|@\"nNh" fullword ascii /* score: '1.00'*/
      $s110 = "8{ir_I" fullword ascii /* score: '1.00'*/
      $s111 = "`^grPo" fullword ascii /* score: '1.00'*/
      $s112 = "Jl9qiimb" fullword ascii /* score: '1.00'*/
      $s113 = "70Eh1YV" fullword ascii /* score: '1.00'*/
      $s114 = "{fuGv\"" fullword ascii /* score: '1.00'*/
      $s115 = "gS{{e{e" fullword ascii /* score: '1.00'*/
      $s116 = "6xv%;I" fullword ascii /* score: '1.00'*/
      $s117 = "K{`87ry" fullword ascii /* score: '1.00'*/
      $s118 = "PE)=TS:9TSF7" fullword ascii /* score: '1.00'*/
      $s119 = "Z6e8{4" fullword ascii /* score: '1.00'*/
      $s120 = "G@0x\"7." fullword ascii /* score: '1.00'*/
      $s121 = "f&z\":E" fullword ascii /* score: '1.00'*/
      $s122 = "Aw!acx^" fullword ascii /* score: '1.00'*/
      $s123 = "3mU4]=" fullword ascii /* score: '1.00'*/
      $s124 = ")$/*w,0" fullword ascii /* score: '1.00'*/
      $s125 = "<Ps;+sh" fullword ascii /* score: '1.00'*/
      $s126 = "&>7M<G" fullword ascii /* score: '1.00'*/
      $s127 = ";s;l*i " fullword ascii /* score: '1.00'*/
      $s128 = "&)ICxZ" fullword ascii /* score: '1.00'*/
      $s129 = ",C~o_D>6," fullword ascii /* score: '1.00'*/
      $s130 = "rXy6&I" fullword ascii /* score: '1.00'*/
      $s131 = "~ `?zZ" fullword ascii /* score: '1.00'*/
      $s132 = "me;TN." fullword ascii /* score: '1.00'*/
      $s133 = "v{h7#2 " fullword ascii /* score: '1.00'*/
      $s134 = "=1[nQH" fullword ascii /* score: '1.00'*/
      $s135 = ",S}8oy;" fullword ascii /* score: '1.00'*/
      $s136 = "\"*#~:e" fullword ascii /* score: '1.00'*/
      $s137 = "zk,EGf'" fullword ascii /* score: '1.00'*/
      $s138 = "AsW{)W" fullword ascii /* score: '1.00'*/
      $s139 = "nDN{#iG" fullword ascii /* score: '1.00'*/
      $s140 = "OoQ+B;" fullword ascii /* score: '1.00'*/
      $s141 = "3k=]G5" fullword ascii /* score: '1.00'*/
      $s142 = "@rC1-v#" fullword ascii /* score: '1.00'*/
      $s143 = "]}!5b`" fullword ascii /* score: '1.00'*/
      $s144 = ".?Qsob" fullword ascii /* score: '1.00'*/
      $s145 = "?8u=wr" fullword ascii /* score: '1.00'*/
      $s146 = "uqu>_t" fullword ascii /* score: '1.00'*/
      $s147 = "?!?\\(I7U" fullword ascii /* score: '1.00'*/
      $s148 = "b$zV`w$Z" fullword ascii /* score: '1.00'*/
      $s149 = "EAg\"}M" fullword ascii /* score: '1.00'*/
      $s150 = "=:`2Yww" fullword ascii /* score: '1.00'*/
      $s151 = "PAQ._0" fullword ascii /* score: '1.00'*/
      $s152 = "vEC!xm!" fullword ascii /* score: '1.00'*/
      $s153 = "lwIOGM" fullword ascii /* score: '1.00'*/
      $s154 = "knc'=d" fullword ascii /* score: '1.00'*/
      $s155 = "8*TM1Z" fullword ascii /* score: '1.00'*/
      $s156 = "6yb!C_" fullword ascii /* score: '1.00'*/
      $s157 = "vO5ijH" fullword ascii /* score: '1.00'*/
      $s158 = "T;8T;xT;xT;HT" fullword ascii /* score: '1.00'*/
      $s159 = "!_qA)S" fullword ascii /* score: '1.00'*/
      $s160 = "i?^2rwk" fullword ascii /* score: '1.00'*/
      $s161 = "z0CiK[a" fullword ascii /* score: '1.00'*/
      $s162 = "W}fzS@,XA" fullword ascii /* score: '1.00'*/
      $s163 = "G?{glR" fullword ascii /* score: '1.00'*/
      $s164 = "4+Z:T>" fullword ascii /* score: '1.00'*/
      $s165 = "'g[yk9" fullword ascii /* score: '1.00'*/
      $s166 = "I;WjF25" fullword ascii /* score: '1.00'*/
      $s167 = "LRq_pn" fullword ascii /* score: '1.00'*/
      $s168 = "{xR35=[l" fullword ascii /* score: '1.00'*/
      $s169 = " ~DrRS" fullword ascii /* score: '1.00'*/
      $s170 = "%Ve@f^" fullword ascii /* score: '1.00'*/
      $s171 = "|f(C@U" fullword ascii /* score: '1.00'*/
      $s172 = "QjghBF" fullword ascii /* score: '1.00'*/
      $s173 = "ABUcx@" fullword ascii /* score: '1.00'*/
      $s174 = "YbBdPL" fullword ascii /* score: '1.00'*/
      $s175 = "i%b5-{" fullword ascii /* score: '1.00'*/
      $s176 = "#(a*:3" fullword ascii /* score: '1.00'*/
      $s177 = "S*a=0*" fullword ascii /* score: '1.00'*/
      $s178 = "Fc:PA\"|" fullword ascii /* score: '1.00'*/
      $s179 = "}KftJ'" fullword ascii /* score: '1.00'*/
      $s180 = "&:n,u?DH3}KD" fullword ascii /* score: '1.00'*/
      $s181 = ".{@u'x" fullword ascii /* score: '1.00'*/
      $s182 = "q+%c$J" fullword ascii /* score: '1.00'*/
      $s183 = "vjO+;N" fullword ascii /* score: '1.00'*/
      $s184 = "=0{p`p" fullword ascii /* score: '1.00'*/
      $s185 = "LU\"\\c6" fullword ascii /* score: '1.00'*/
      $s186 = "=gp!S)c`I+" fullword ascii /* score: '1.00'*/
      $s187 = "YH?WYqz" fullword ascii /* score: '1.00'*/
      $s188 = "w.}y'zA" fullword ascii /* score: '1.00'*/
      $s189 = "^5lhe1" fullword ascii /* score: '1.00'*/
      $s190 = "Ql p@QjL" fullword ascii /* score: '1.00'*/
      $s191 = "4[,a5c" fullword ascii /* score: '1.00'*/
      $s192 = "tK_8Z4" fullword ascii /* score: '1.00'*/
      $s193 = ".}D!DD" fullword ascii /* score: '1.00'*/
      $s194 = "[Ut?9z" fullword ascii /* score: '1.00'*/
      $s195 = "lSxJ*9" fullword ascii /* score: '1.00'*/
      $s196 = "=-RN7N" fullword ascii /* score: '1.00'*/
      $s197 = "IX6MLx" fullword ascii /* score: '1.00'*/
      $s198 = "qve>Rx" fullword ascii /* score: '1.00'*/
      $s199 = "Iw_F@V?" fullword ascii /* score: '1.00'*/
      $s200 = "G&$RcK" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 500KB and
      8 of them
}

rule sig_1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061 {
   meta:
      description = "Amadey_MALW - file 1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061"
   strings:
      $s1 = "word/_rels/vbaProject.bin.relsPK" fullword ascii /* score: '10.00'*/
      $s2 = "word/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s3 = "word/_rels/vbaProject.bin.relsl" fullword ascii /* score: '10.00'*/
      $s4 = "word/vbaData.xml" fullword ascii /* score: '7.00'*/
      $s5 = "word/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s6 = "word/vbaData.xmlPK" fullword ascii /* score: '4.00'*/
      $s7 = "word/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "word/webSettings.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "word/fontTable.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "word/document.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "word/settings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "word/webSettings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "word/_rels/document.xml.rels " fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "F7,gw9[.\"s`" fullword ascii /* score: '1.00'*/
      $s18 = "%^c^l$x" fullword ascii /* score: '1.00'*/
      $s19 = "/L[E'9" fullword ascii /* score: '1.00'*/
      $s20 = "]?cv0$G" fullword ascii /* score: '1.00'*/
      $s21 = ".|}PdI" fullword ascii /* score: '1.00'*/
      $s22 = "ARXZ[-" fullword ascii /* score: '1.00'*/
      $s23 = "Pzz1xa" fullword ascii /* score: '1.00'*/
      $s24 = "X=c+(\\" fullword ascii /* score: '1.00'*/
      $s25 = "wR6e:G{" fullword ascii /* score: '1.00'*/
      $s26 = "-\\Ya;>>" fullword ascii /* score: '1.00'*/
      $s27 = "Bot*k^" fullword ascii /* score: '1.00'*/
      $s28 = "6Gda@j" fullword ascii /* score: '1.00'*/
      $s29 = "Q)aaT2X" fullword ascii /* score: '1.00'*/
      $s30 = "XXdYkj" fullword ascii /* score: '1.00'*/
      $s31 = "n!td[;" fullword ascii /* score: '1.00'*/
      $s32 = "`4n=Jc" fullword ascii /* score: '1.00'*/
      $s33 = "D/'!5>d" fullword ascii /* score: '1.00'*/
      $s34 = "*E{M][HUUEs*" fullword ascii /* score: '1.00'*/
      $s35 = "S)wg=s=" fullword ascii /* score: '1.00'*/
      $s36 = ";d/&\\j\\" fullword ascii /* score: '1.00'*/
      $s37 = "d}}) tMG" fullword ascii /* score: '1.00'*/
      $s38 = "5}4Onb" fullword ascii /* score: '1.00'*/
      $s39 = "++J1#A" fullword ascii /* score: '1.00'*/
      $s40 = "6 4hG(" fullword ascii /* score: '1.00'*/
      $s41 = "word/styles.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s42 = "word/fontTable.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s43 = "word/settings.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s44 = "word/document.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x4b50 and filesize < 50KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf_d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd306_0 {
   meta:
      description = "Amadey_MALW - from files 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf, d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b, 707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6, ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10, 4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515, 2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
      hash2 = "d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b"
      hash3 = "707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6"
      hash4 = "ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10"
      hash5 = "4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
      hash6 = "2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
   strings:
      $s1 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s2 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s3 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s4 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s5 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s6 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s7 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii /* score: '7.00'*/
      $s8 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii /* score: '7.00'*/
      $s9 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii /* score: '7.00'*/
      $s10 = "RSDSwb6" fullword ascii /* score: '5.00'*/
      $s11 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s12 = "Extracting" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 13 times */
      $s13 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s14 = "Extract" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 42 times */
      $s15 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s16 = "PendingFileRenameOperations" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 52 times */
      $s17 = "RegServer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.94'*/ /* Goodware String - occured 57 times */
      $s18 = "Reboot" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 105 times */
      $s19 = "SeShutdownPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s20 = "Internet Explorer" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 518 times */
      $s21 = "=\">>>G>R>Y>p>v>|>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s22 = "?+?1?<?B?N?^?g?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s23 = "?e?q?}?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s24 = ".rdata$brc" fullword ascii /* score: '4.00'*/
      $s25 = "WWj WWWSW" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s26 = ";#;/;5;<;E;K;S;Y;f;n;t;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s27 = "11.00.14393.0 (rs1_release.160715-1616)" fullword wide /* score: '4.00'*/
      $s28 = "WEXTRACT.EXE            .MUI" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s29 = "            <!--This Id value indicates the application supports Windows 7/Server 2008 R2 functionality-->" fullword ascii /* score: '3.00'*/
      $s30 = "D$HjDj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s31 = "00(0y0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s32 = ":<\\u6:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s33 = "SSh`2@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s34 = "33(313F3[3h3p3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s35 = "<At <Bt" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s36 = "            <!--This Id value indicates the application supports Windows 8/Server 2012 functionality-->" fullword ascii /* score: '3.00'*/
      $s37 = "          level=\"asInvoker\"" fullword ascii /* score: '3.00'*/
      $s38 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii /* score: '2.00'*/
      $s39 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " fullword ascii /* score: '2.00'*/
      $s40 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s41 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii /* score: '2.00'*/
      $s42 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii /* score: '2.00'*/
      $s43 = "PA<None>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s44 = "    </compatibility>" fullword ascii /* score: '2.00'*/
      $s45 = "5D5S5c5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s46 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s47 = "0(0K0f0" fullword ascii /* score: '1.00'*/
      $s48 = ":+:1:D:L:" fullword ascii /* score: '1.00'*/
      $s49 = "<.<E<M<V<[<`<v<|<" fullword ascii /* score: '1.00'*/
      $s50 = "3)40494D4`4" fullword ascii /* score: '1.00'*/
      $s51 = ":6:N:S:r:" fullword ascii /* score: '1.00'*/
      $s52 = "=\"=(=2=M={=" fullword ascii /* score: '1.00'*/
      $s53 = "?(?9?H?W?c?y?" fullword ascii /* score: '1.00'*/
      $s54 = "3$303f3r3~3" fullword ascii /* score: '1.00'*/
      $s55 = "8&8,878R8^8|8" fullword ascii /* score: '1.00'*/
      $s56 = "60L0_0k0r0" fullword ascii /* score: '1.00'*/
      $s57 = "0W0j0p0x0" fullword ascii /* score: '1.00'*/
      $s58 = "6#676>6D6K6P6W6_6d6" fullword ascii /* score: '1.00'*/
      $s59 = "9*:::G:c:l:~:" fullword ascii /* score: '1.00'*/
      $s60 = "; <*<0<6<<<D<J<V<" fullword ascii /* score: '1.00'*/
      $s61 = "6%6J6d6" fullword ascii /* score: '1.00'*/
      $s62 = "t3WWh@1@" fullword ascii /* score: '1.00'*/
      $s63 = "3>3]3p3" fullword ascii /* score: '1.00'*/
      $s64 = "=2=\\=k=y=" fullword ascii /* score: '1.00'*/
      $s65 = "<9<H<N<W<^<s<" fullword ascii /* score: '1.00'*/
      $s66 = "0,121}1" fullword ascii /* score: '1.00'*/
      $s67 = "<<<`<o<|<" fullword ascii /* score: '1.00'*/
      $s68 = "1'1-13181?1O1Z1`1x1" fullword ascii /* score: '1.00'*/
      $s69 = "0$0*030H0N0m0x0" fullword ascii /* score: '1.00'*/
      $s70 = "1.191@1K1]1f1" fullword ascii /* score: '1.00'*/
      $s71 = ">!?(?G?R?g?" fullword ascii /* score: '1.00'*/
      $s72 = "7C8`8l8" fullword ascii /* score: '1.00'*/
      $s73 = ";#;7;@;I;R;q;~;" fullword ascii /* score: '1.00'*/
      $s74 = "0X1k1r1" fullword ascii /* score: '1.00'*/
      $s75 = "8)8@8W8^8" fullword ascii /* score: '1.00'*/
      $s76 = ";%;C;O;" fullword ascii /* score: '1.00'*/
      $s77 = "5:5I5Z5c5" fullword ascii /* score: '1.00'*/
      $s78 = "<+<C<k<y<" fullword ascii /* score: '1.00'*/
      $s79 = "545@5o5|5" fullword ascii /* score: '1.00'*/
      $s80 = "4'4?4J4V4c4" fullword ascii /* score: '1.00'*/
      $s81 = "2'2,262j2}2" fullword ascii /* score: '1.00'*/
      $s82 = "3&3-333Q3Z3m3u3" fullword ascii /* score: '1.00'*/
      $s83 = "Sj@Sh " fullword ascii /* score: '1.00'*/
      $s84 = "3\"3A3M3V3_3o3w3" fullword ascii /* score: '1.00'*/
      $s85 = ">#>C>R>^>f>r>" fullword ascii /* score: '1.00'*/
      $s86 = "7$7-747F7P7" fullword ascii /* score: '1.00'*/
      $s87 = "4!4:4D4S4Z4g4" fullword ascii /* score: '1.00'*/
      $s88 = "PAD<None>" fullword ascii /* score: '1.00'*/
      $s89 = "=.=>=C=H=o=u={=" fullword ascii /* score: '1.00'*/
      $s90 = "313>3\\3" fullword ascii /* score: '1.00'*/
      $s91 = "D$<tXh" fullword ascii /* score: '1.00'*/
      $s92 = "202<2H2O2u2" fullword ascii /* score: '1.00'*/
      $s93 = ">T>f>y>" fullword ascii /* score: '1.00'*/
      $s94 = "787D7O7[7" fullword ascii /* score: '1.00'*/
      $s95 = ">*>?>E>K>Z>u>}>" fullword ascii /* score: '1.00'*/
      $s96 = "9*979^9o9" fullword ascii /* score: '1.00'*/
      $s97 = ":+:L:S:t:" fullword ascii /* score: '1.00'*/
      $s98 = ";-;<;I;`;" fullword ascii /* score: '1.00'*/
      $s99 = "0D0H0P0X0" fullword ascii /* score: '1.00'*/
      $s100 = "0#121W1e1" fullword ascii /* score: '1.00'*/
      $s101 = "1*2E2M2\\2c2z2" fullword ascii /* score: '1.00'*/
      $s102 = "WWhPP@" fullword ascii /* score: '1.00'*/
      $s103 = "='=7===l=" fullword ascii /* score: '1.00'*/
      $s104 = "5/5<5f5r5" fullword ascii /* score: '1.00'*/
      $s105 = "=$=2=z=" fullword ascii /* score: '1.00'*/
      $s106 = "9=9S9i9u9|9" fullword ascii /* score: '1.00'*/
      $s107 = "?<?C?t?~?" fullword ascii /* score: '1.00'*/
      $s108 = ";$;9;M;S;w;" fullword ascii /* score: '1.00'*/
      $s109 = "11.00.14393.0" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "1efe015ade03f54dd6d9b2ccea28b970" and ( 8 of them )
      ) or ( all of them )
}

rule _7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d_8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b_1 {
   meta:
      description = "Amadey_MALW - from files 7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d, 8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d"
      hash2 = "8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197"
   strings:
      $s1 = "?GetProcessWindowStation" fullword ascii /* score: '20.00'*/
      $s2 = "C:\\halewupesi_xafidehusef\\57\\molaj\\yawavilunu-48\\goyu.pdb" fullword ascii /* score: '20.00'*/
      $s3 = "vuvugojonofisajihepucejekexuzewoyicuweweyevucaceyu" fullword ascii /* score: '9.00'*/
      $s4 = ".Yosumaxezepuh bacoseyeyen wobil wutuxuhocinicu" fullword wide /* score: '9.00'*/
      $s5 = "hozasilor" fullword wide /* score: '8.00'*/
      $s6 = "foxacirizip" fullword wide /* score: '8.00'*/
      $s7 = "jewuwomekorecokoyujesac" fullword wide /* score: '8.00'*/
      $s8 = "pazefovatasodobuzuhoxutirivejehi" fullword wide /* score: '8.00'*/
      $s9 = "jijozumadik" fullword wide /* score: '8.00'*/
      $s10 = "Puzahirubehubin1Duconobajaz mexafa pigoyu xojedeluxop ruy tetokuz" fullword wide /* score: '7.00'*/
      $s11 = "FilesVersion" fullword wide /* score: '7.00'*/
      $s12 = "pohuyis sofog lesamuwaliy" fullword wide /* score: '6.00'*/
      $s13 = "ilufen foficoju wixoli" fullword wide /* score: '6.00'*/
      $s14 = "25.55.47.80" fullword wide /* score: '6.00'*/
      $s15 = "\"sQ -;" fullword ascii /* score: '5.00'*/
      $s16 = "FHohuji jafiri posumowa masugi sogicijizu gunuyobo kavewab xeyevexubixuCHubupoduyixama kijozusahesi bosifuhukusum vinoy pediw mi" wide /* score: '5.00'*/
      $s17 = "uoFB~r+0" fullword ascii /* score: '4.00'*/
      $s18 = "rfHu)T*" fullword ascii /* score: '4.00'*/
      $s19 = "xKsy4%'-*" fullword ascii /* score: '4.00'*/
      $s20 = "g%T.VDt" fullword ascii /* score: '4.00'*/
      $s21 = "cXOX\\Z" fullword ascii /* score: '4.00'*/
      $s22 = "kzYa)\\}RY" fullword ascii /* score: '4.00'*/
      $s23 = "LhyT/VT" fullword ascii /* score: '4.00'*/
      $s24 = "RZirYIj=n" fullword ascii /* score: '4.00'*/
      $s25 = "GwWDTH!DwY" fullword ascii /* score: '4.00'*/
      $s26 = "lylC-QYE" fullword ascii /* score: '4.00'*/
      $s27 = "'ugmV!cm" fullword ascii /* score: '4.00'*/
      $s28 = "~:jHVn\\Wm" fullword ascii /* score: '4.00'*/
      $s29 = "fDmf}C)" fullword ascii /* score: '4.00'*/
      $s30 = "uJsJ\"x" fullword ascii /* score: '4.00'*/
      $s31 = "AjFSe H" fullword ascii /* score: '4.00'*/
      $s32 = "vfkmdoz," fullword ascii /* score: '4.00'*/
      $s33 = "bDRVT|0J&" fullword ascii /* score: '4.00'*/
      $s34 = "MFdp'Ii" fullword ascii /* score: '4.00'*/
      $s35 = "Oxfyfi-" fullword ascii /* score: '4.00'*/
      $s36 = "cagapizagesi" fullword wide /* score: '4.00'*/
      $s37 = "KJuf sub lojuruvono wuhoyekuwuw ruyami yakotujusifaru voxekuvecopig lunezovo" fullword wide /* score: '4.00'*/
      $s38 = "7Jobat jusomekaru yaledijip dujekaberozogo kadabefutabek" fullword wide /* score: '4.00'*/
      $s39 = "Bikazoyo vatuwefeyopuyaw siwa" fullword wide /* score: '4.00'*/
      $s40 = "Hola arifmeco soft" fullword wide /* score: '4.00'*/
      $s41 = "\\=R`v^" fullword ascii /* score: '2.00'*/
      $s42 = "\\ktKd`" fullword ascii /* score: '2.00'*/
      $s43 = "\\kiB,?DF" fullword ascii /* score: '2.00'*/
      $s44 = "WxwY29" fullword ascii /* score: '2.00'*/
      $s45 = "\\pgrZ>" fullword ascii /* score: '2.00'*/
      $s46 = "uWkJM7" fullword ascii /* score: '2.00'*/
      $s47 = ":T//oA" fullword ascii /* score: '1.00'*/
      $s48 = ")h-t/C" fullword ascii /* score: '1.00'*/
      $s49 = "8^1t{.BN" fullword ascii /* score: '1.00'*/
      $s50 = "609[wB" fullword ascii /* score: '1.00'*/
      $s51 = "ncS\\u2" fullword ascii /* score: '1.00'*/
      $s52 = "o$s_f#" fullword ascii /* score: '1.00'*/
      $s53 = "{SB`L[" fullword ascii /* score: '1.00'*/
      $s54 = "!fI*~?kU" fullword ascii /* score: '1.00'*/
      $s55 = "}(D Uh" fullword ascii /* score: '1.00'*/
      $s56 = "A%S3*8Rv" fullword ascii /* score: '1.00'*/
      $s57 = ":=@{ z" fullword ascii /* score: '1.00'*/
      $s58 = "l&KWSJ" fullword ascii /* score: '1.00'*/
      $s59 = "\"I+OW3P" fullword ascii /* score: '1.00'*/
      $s60 = "gKTF~R" fullword ascii /* score: '1.00'*/
      $s61 = ">bG<\"=" fullword ascii /* score: '1.00'*/
      $s62 = "9!O#)y~" fullword ascii /* score: '1.00'*/
      $s63 = "d##,;)" fullword ascii /* score: '1.00'*/
      $s64 = "^%iW)nZ" fullword ascii /* score: '1.00'*/
      $s65 = "@~.^iuW" fullword ascii /* score: '1.00'*/
      $s66 = "2#s5G-\"" fullword ascii /* score: '1.00'*/
      $s67 = "9xw:4?" fullword ascii /* score: '1.00'*/
      $s68 = "62byL8" fullword ascii /* score: '1.00'*/
      $s69 = "Vm6lU`" fullword ascii /* score: '1.00'*/
      $s70 = "auc[w>8bZJ" fullword ascii /* score: '1.00'*/
      $s71 = ">`O#aY" fullword ascii /* score: '1.00'*/
      $s72 = "U[]T`B" fullword ascii /* score: '1.00'*/
      $s73 = ">L@F3{L" fullword ascii /* score: '1.00'*/
      $s74 = "{]g)N;u" fullword ascii /* score: '1.00'*/
      $s75 = "2_Gz!k" fullword ascii /* score: '1.00'*/
      $s76 = "EZ2:/z" fullword ascii /* score: '1.00'*/
      $s77 = "y+L,W>/" fullword ascii /* score: '1.00'*/
      $s78 = "8QW[R.f" fullword ascii /* score: '1.00'*/
      $s79 = "x:4hOCJ{" fullword ascii /* score: '1.00'*/
      $s80 = "~'o@V|" fullword ascii /* score: '1.00'*/
      $s81 = "b'VP5S" fullword ascii /* score: '1.00'*/
      $s82 = "#24C?Q" fullword ascii /* score: '1.00'*/
      $s83 = "Cp3j.a@" fullword ascii /* score: '1.00'*/
      $s84 = "{]!j9@z" fullword ascii /* score: '1.00'*/
      $s85 = "]iG6RPK*>,P" fullword ascii /* score: '1.00'*/
      $s86 = "Tx[wQX[" fullword ascii /* score: '1.00'*/
      $s87 = "(NG$i\"" fullword ascii /* score: '1.00'*/
      $s88 = "3TQeeS" fullword ascii /* score: '1.00'*/
      $s89 = "CxQnpq" fullword ascii /* score: '1.00'*/
      $s90 = "|[yQK(" fullword ascii /* score: '1.00'*/
      $s91 = "sz)&$o" fullword ascii /* score: '1.00'*/
      $s92 = "YYh$)@" fullword ascii /* score: '1.00'*/
      $s93 = "*\"YY0?" fullword ascii /* score: '1.00'*/
      $s94 = "Jo7Fl$`cH" fullword ascii /* score: '1.00'*/
      $s95 = ")o7&H+s" fullword ascii /* score: '1.00'*/
      $s96 = "$tPS40" fullword ascii /* score: '1.00'*/
      $s97 = "^g][0O" fullword ascii /* score: '1.00'*/
      $s98 = "B{=Ug9,." fullword ascii /* score: '1.00'*/
      $s99 = "'@kx}/1" fullword ascii /* score: '1.00'*/
      $s100 = "xwY#8}" fullword ascii /* score: '1.00'*/
      $s101 = "lU%Fz9P" fullword ascii /* score: '1.00'*/
      $s102 = "k!rY,|Z" fullword ascii /* score: '1.00'*/
      $s103 = "}-bGU4" fullword ascii /* score: '1.00'*/
      $s104 = "q02l? P" fullword ascii /* score: '1.00'*/
      $s105 = "!diTdv" fullword ascii /* score: '1.00'*/
      $s106 = "ler`73f" fullword ascii /* score: '1.00'*/
      $s107 = "!CqK$E" fullword ascii /* score: '1.00'*/
      $s108 = "Ouf~nl" fullword ascii /* score: '1.00'*/
      $s109 = "qDv=iW" fullword ascii /* score: '1.00'*/
      $s110 = "[@B^~;Ka`:" fullword ascii /* score: '1.00'*/
      $s111 = "Z%M8-." fullword ascii /* score: '1.00'*/
      $s112 = "C3d._%\"" fullword ascii /* score: '1.00'*/
      $s113 = "^S?HVt8" fullword ascii /* score: '1.00'*/
      $s114 = "4g\\KYC" fullword ascii /* score: '1.00'*/
      $s115 = "3-dSbS^A" fullword ascii /* score: '1.00'*/
      $s116 = "Fh;#[/" fullword ascii /* score: '1.00'*/
      $s117 = "/\\&_`(q" fullword ascii /* score: '1.00'*/
      $s118 = "w?lT\"*q" fullword ascii /* score: '1.00'*/
      $s119 = "QMs&DTy" fullword ascii /* score: '1.00'*/
      $s120 = "2{X\"I=" fullword ascii /* score: '1.00'*/
      $s121 = "OoTK]u" fullword ascii /* score: '1.00'*/
      $s122 = "1_\"uKG" fullword ascii /* score: '1.00'*/
      $s123 = "<@T5w," fullword ascii /* score: '1.00'*/
      $s124 = "8/Z{Qt" fullword ascii /* score: '1.00'*/
      $s125 = "ppC4l_[" fullword ascii /* score: '1.00'*/
      $s126 = "3\"v=e{" fullword ascii /* score: '1.00'*/
      $s127 = "!X}Mt$$sl3" fullword ascii /* score: '1.00'*/
      $s128 = "r3DUyp&5" fullword ascii /* score: '1.00'*/
      $s129 = ";PAz(g" fullword ascii /* score: '1.00'*/
      $s130 = "Q|qqah" fullword ascii /* score: '1.00'*/
      $s131 = "n5^K{9" fullword ascii /* score: '1.00'*/
      $s132 = "baWp$p" fullword ascii /* score: '1.00'*/
      $s133 = "*W_-d-" fullword ascii /* score: '1.00'*/
      $s134 = "fm?i<4" fullword ascii /* score: '1.00'*/
      $s135 = "w)ZgHv" fullword ascii /* score: '1.00'*/
      $s136 = "}ra!l+" fullword ascii /* score: '1.00'*/
      $s137 = "JBF}(O2" fullword ascii /* score: '1.00'*/
      $s138 = "dj>_`[" fullword ascii /* score: '1.00'*/
      $s139 = "BW}~]1" fullword ascii /* score: '1.00'*/
      $s140 = "Jc|(By" fullword ascii /* score: '1.00'*/
      $s141 = "QV(6&Ik" fullword ascii /* score: '1.00'*/
      $s142 = "%+o@;{" fullword ascii /* score: '1.00'*/
      $s143 = "mCQVAv" fullword ascii /* score: '1.00'*/
      $s144 = "VK:^5S" fullword ascii /* score: '1.00'*/
      $s145 = "PinL]o" fullword ascii /* score: '1.00'*/
      $s146 = "6v70W@" fullword ascii /* score: '1.00'*/
      $s147 = "}&f' c" fullword ascii /* score: '1.00'*/
      $s148 = "56l6|t" fullword ascii /* score: '1.00'*/
      $s149 = "zPt|Iu" fullword ascii /* score: '1.00'*/
      $s150 = "_N}MT}" fullword ascii /* score: '1.00'*/
      $s151 = "DK!K^&G" fullword ascii /* score: '1.00'*/
      $s152 = "#e}r9ia" fullword ascii /* score: '1.00'*/
      $s153 = ":xC(S0" fullword ascii /* score: '1.00'*/
      $s154 = "P{^N^#" fullword ascii /* score: '1.00'*/
      $s155 = "wB0)p." fullword ascii /* score: '1.00'*/
      $s156 = "=]I,B}" fullword ascii /* score: '1.00'*/
      $s157 = "IxD9STWV" fullword ascii /* score: '1.00'*/
      $s158 = ".naEoO" fullword ascii /* score: '1.00'*/
      $s159 = "^K&u,}~" fullword ascii /* score: '1.00'*/
      $s160 = "F%i+UK" fullword ascii /* score: '1.00'*/
      $s161 = "dV3rFM" fullword ascii /* score: '1.00'*/
      $s162 = "%Rf~>?XJ" fullword ascii /* score: '1.00'*/
      $s163 = "P'*'j _@" fullword ascii /* score: '1.00'*/
      $s164 = ">TtJ}o" fullword ascii /* score: '1.00'*/
      $s165 = "%kYVbv" fullword ascii /* score: '1.00'*/
      $s166 = "wN SMq" fullword ascii /* score: '1.00'*/
      $s167 = "({qh.1" fullword ascii /* score: '1.00'*/
      $s168 = "O4\"s&$-P" fullword ascii /* score: '1.00'*/
      $s169 = "$py2>j" fullword ascii /* score: '1.00'*/
      $s170 = "8Mm&Buh" fullword ascii /* score: '1.00'*/
      $s171 = "? 98e<Q" fullword ascii /* score: '1.00'*/
      $s172 = "WEy83#CtJ" fullword ascii /* score: '1.00'*/
      $s173 = "}/\\hdZ" fullword ascii /* score: '1.00'*/
      $s174 = "9)?ysT" fullword ascii /* score: '1.00'*/
      $s175 = "@pR^o?%" fullword ascii /* score: '1.00'*/
      $s176 = "Vy~r%r" fullword ascii /* score: '1.00'*/
      $s177 = "+Pz!g1" fullword ascii /* score: '1.00'*/
      $s178 = "2j<TB7" fullword ascii /* score: '1.00'*/
      $s179 = "`t;IDB~a4" fullword ascii /* score: '1.00'*/
      $s180 = "O2Te-u" fullword ascii /* score: '1.00'*/
      $s181 = "tr>![]" fullword ascii /* score: '1.00'*/
      $s182 = "j~f.]8" fullword ascii /* score: '1.00'*/
      $s183 = "j1^w)mx" fullword ascii /* score: '1.00'*/
      $s184 = "uSO\"'Qh" fullword ascii /* score: '1.00'*/
      $s185 = "wN|3{Q" fullword ascii /* score: '1.00'*/
      $s186 = "IgF#Mzb" fullword ascii /* score: '1.00'*/
      $s187 = "4#]Lq*5" fullword ascii /* score: '1.00'*/
      $s188 = "?4rIB&" fullword ascii /* score: '1.00'*/
      $s189 = "6^j>J%" fullword ascii /* score: '1.00'*/
      $s190 = "Hkmqg-" fullword ascii /* score: '1.00'*/
      $s191 = "3'{8jkI" fullword ascii /* score: '1.00'*/
      $s192 = "U-zn2v" fullword ascii /* score: '1.00'*/
      $s193 = "}z{LxD?X!" fullword ascii /* score: '1.00'*/
      $s194 = "oOORU{" fullword ascii /* score: '1.00'*/
      $s195 = "Tva3ti" fullword ascii /* score: '1.00'*/
      $s196 = "_K=ruG" fullword ascii /* score: '1.00'*/
      $s197 = ":.h^U4" fullword ascii /* score: '1.00'*/
      $s198 = ";T+Zv-:X" fullword ascii /* score: '1.00'*/
      $s199 = " {);(N" fullword ascii /* score: '1.00'*/
      $s200 = "-hpQs<" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "48f236213eba53981d8d663c1043055b" and ( 8 of them )
      ) or ( all of them )
}

rule _12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1_488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791_2 {
   meta:
      description = "Amadey_MALW - from files 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1, 488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77, 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c, 919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226, ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
      hash2 = "488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
      hash3 = "5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
      hash4 = "919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
      hash5 = "ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "vector too long" fullword ascii /* score: '6.00'*/
      $s3 = "list too long" fullword ascii /* score: '6.00'*/
      $s4 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" fullword ascii /* score: '5.00'*/
      $s5 = ".?AV?$_Func_impl_no_alloc@V?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@X$$V@std@@" fullword ascii /* score: '5.00'*/
      $s6 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s7 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s8 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s9 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s10 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s11 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s12 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s13 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s14 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s15 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s16 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s17 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s18 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
      $s19 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" fullword ascii /* score: '4.00'*/
      $s20 = "cy@@@?$task@E@Concurrency@@U_TaskProcHandle@details@3@@details@Concurrency@@" fullword ascii /* score: '4.00'*/
      $s21 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" fullword ascii /* score: '4.00'*/
      $s22 = ".?AV_ExceptionPtr_normal@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s23 = ".?AV?$_Func_impl_no_alloc@V<lambda_0456396a71e3abd88ede77bdd2823d8e>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s24 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s25 = ".?AV?$_Ref_count_obj2@U_ExceptionHolder@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s26 = ".?AV?$_Func_impl_no_alloc@V<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@E$$V@std@@" fullword ascii /* score: '4.00'*/
      $s27 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s28 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0x03848f66@@" fullword ascii /* score: '4.00'*/
      $s29 = ".?AV?$_Func_impl_no_alloc@V<lambda_9de88c4009318ef1202283857f94e673>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s30 = ".?AV?$_Ref_count_obj2@U?$_Task_impl@E@details@Concurrency@@@std@@" fullword ascii /* score: '4.00'*/
      $s31 = "FYY;w(|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s32 = ".?AU?$_PPLTaskHandle@EU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurren" ascii /* score: '4.00'*/
      $s33 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s34 = "rrency@@" fullword ascii /* score: '4.00'*/
      $s35 = ".?AV?$_Task_async_state@X@std@@" fullword ascii /* score: '4.00'*/
      $s36 = ".?AV?$_Func_impl_no_alloc@V<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s37 = "Wj4XPV" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s38 = ".?AU?$_InitialTaskHandle@XV<lambda_9de88c4009318ef1202283857f94e673>@@U_TypeSelectorNoAsync@details@Concurrency@@@?$task@E@Concu" ascii /* score: '4.00'*/
      $s39 = "YYF;w,|" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s40 = ".?AV?$_Func_impl_no_alloc@V<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@X$$V@std@@" fullword ascii /* score: '4.00'*/
      $s41 = "Eapi-ms-win-core-fibers-l1-1-1" fullword wide /* score: '4.00'*/
      $s42 = "Eapi-ms-win-core-datetime-l1-1-1" fullword wide /* score: '4.00'*/
      $s43 = "system" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.42'*/ /* Goodware String - occured 1577 times */
      $s44 = ";1#INF" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s45 = "9de88c4009318ef1202283857f94e673" ascii /* score: '3.00'*/
      $s46 = ".?AV?$_Func_base@E$$V@std@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s47 = ".?AV?$_CancellationTokenCallback@V<lambda_3b8ab8d2629adf61a42ee3fe177a046b>@@@details@Concurrency@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s48 = "3b8ab8d2629adf61a42ee3fe177a046b" ascii /* score: '3.00'*/
      $s49 = "7c33b2c4310ad8c6be497d7a2a561bb8" ascii /* score: '3.00'*/
      $s50 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s51 = "eb87dfd73f857f44e1a351ea42ce2b34" ascii /* score: '3.00'*/
      $s52 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s53 = "0456396a71e3abd88ede77bdd2823d8e" ascii /* score: '3.00'*/
      $s54 = "5e5ab22ea98f4361dbf159481d01f54d" ascii /* score: '3.00'*/
      $s55 = ".?AV<lambda_7c33b2c4310ad8c6be497d7a2a561bb8>@@" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s56 = "Eja-JP" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s57 = "Sk{$4kK(4" fullword ascii /* score: '1.00'*/
      $s58 = ".?AV_DefaultPPLTaskScheduler@details@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s59 = "20242`7d7h7l7p7t7x7|7" fullword ascii /* score: '1.00'*/
      $s60 = ";{dv(2" fullword ascii /* score: '1.00'*/
      $s61 = "This function cannot be called on a default constructed task" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s62 = "u78Gdt" fullword ascii /* score: '1.00'*/
      $s63 = "SPjdVQ" fullword ascii /* score: '1.00'*/
      $s64 = "kG$4kW(4" fullword ascii /* score: '1.00'*/
      $s65 = "tB;wPt" fullword ascii /* score: '1.00'*/
      $s66 = "9V(~Bj" fullword ascii /* score: '1.00'*/
      $s67 = "u28C`t" fullword ascii /* score: '1.00'*/
      $s68 = "9318ef1202283857f94e673" ascii /* score: '1.00'*/
      $s69 = ");{0t3" fullword ascii /* score: '1.00'*/
      $s70 = "BHkW($" fullword ascii /* score: '1.00'*/
      $s71 = "A<lt'<tt" fullword ascii /* score: '1.00'*/
      $s72 = "Q;FD~Z" fullword ascii /* score: '1.00'*/
      $s73 = ".?AVstl_condition_variable_win7@details@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s74 = "9V(~?j" fullword ascii /* score: '1.00'*/
      $s75 = "u<9Fpt" fullword ascii /* score: '1.00'*/
      $s76 = "4Q;FD~Z" fullword ascii /* score: '1.00'*/
      $s77 = "9pdt>V" fullword ascii /* score: '1.00'*/
      $s78 = "<ItC<Lt3<Tt#<h" fullword ascii /* score: '1.00'*/
      $s79 = "uN9Fpt" fullword ascii /* score: '1.00'*/
      $s80 = ".?AUscheduler_interface@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s81 = "tl=`'F" fullword ascii /* score: '1.00'*/
      $s82 = "tO9xp~J" fullword ascii /* score: '1.00'*/
      $s83 = "Q;FD~R" fullword ascii /* score: '1.00'*/
      $s84 = ".?AVstl_critical_section_win7@details@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s85 = "F,H_[u" fullword ascii /* score: '1.00'*/
      $s86 = ".?AVstl_condition_variable_concrt@details@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s87 = ".?AVstl_critical_section_concrt@details@Concurrency@@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s88 = "9V(~>j" fullword ascii /* score: '1.00'*/
      $s89 = ".?AVstl_critical_section_interface@details@Concurrency@@" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s90 = ".?AVstl_critical_section_vista@details@Concurrency@@" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s91 = ".?AVstl_condition_variable_vista@details@Concurrency@@" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s92 = ".?AVstl_condition_variable_interface@details@Concurrency@@" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s93 = "Akernel32.dll" fullword wide /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf_d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd306_3 {
   meta:
      description = "Amadey_MALW - from files 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf, d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
      hash2 = "d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b"
   strings:
      $s1 = "P?IanI2v6" fullword ascii /* score: '4.00'*/
      $s2 = "hvyZ2U` " fullword ascii /* score: '4.00'*/
      $s3 = "(%LVHP5=(" fullword ascii /* score: '4.00'*/
      $s4 = "egFO$QQ" fullword ascii /* score: '4.00'*/
      $s5 = "!:%S[w" fullword ascii /* score: '4.00'*/
      $s6 = "eEbW1Q9M" fullword ascii /* score: '4.00'*/
      $s7 = "3fScr@:'" fullword ascii /* score: '4.00'*/
      $s8 = "ySiHt,8h" fullword ascii /* score: '4.00'*/
      $s9 = "hTwc\\1," fullword ascii /* score: '4.00'*/
      $s10 = "lLbO{v*" fullword ascii /* score: '4.00'*/
      $s11 = "\\DpQ-L_F" fullword ascii /* score: '2.00'*/
      $s12 = "79+upM" fullword ascii /* score: '1.00'*/
      $s13 = "!2MQC{b" fullword ascii /* score: '1.00'*/
      $s14 = "X1'@)y" fullword ascii /* score: '1.00'*/
      $s15 = "ATJ&Nb" fullword ascii /* score: '1.00'*/
      $s16 = "+|[9GS5" fullword ascii /* score: '1.00'*/
      $s17 = "/O(,\"K" fullword ascii /* score: '1.00'*/
      $s18 = "}9'(UQ" fullword ascii /* score: '1.00'*/
      $s19 = "<.|@(0" fullword ascii /* score: '1.00'*/
      $s20 = "#qCqFX" fullword ascii /* score: '1.00'*/
      $s21 = "/@t0X=" fullword ascii /* score: '1.00'*/
      $s22 = "pM$mEV" fullword ascii /* score: '1.00'*/
      $s23 = " kcv/Z^" fullword ascii /* score: '1.00'*/
      $s24 = "=qC^Qb" fullword ascii /* score: '1.00'*/
      $s25 = "rR|Vyr" fullword ascii /* score: '1.00'*/
      $s26 = "QAu^GJ" fullword ascii /* score: '1.00'*/
      $s27 = "kk*7~Gs" fullword ascii /* score: '1.00'*/
      $s28 = "a!=6km" fullword ascii /* score: '1.00'*/
      $s29 = "4xkIFm" fullword ascii /* score: '1.00'*/
      $s30 = "g;*K6%" fullword ascii /* score: '1.00'*/
      $s31 = "r/\",G`" fullword ascii /* score: '1.00'*/
      $s32 = "m\\*0uv" fullword ascii /* score: '1.00'*/
      $s33 = "(FU.wV" fullword ascii /* score: '1.00'*/
      $s34 = ":Fy49L" fullword ascii /* score: '1.00'*/
      $s35 = "=$DO]I" fullword ascii /* score: '1.00'*/
      $s36 = "uNU>s9i" fullword ascii /* score: '1.00'*/
      $s37 = "Y,Q+Ib" fullword ascii /* score: '1.00'*/
      $s38 = "%hIcdl" fullword ascii /* score: '1.00'*/
      $s39 = "StA}w:L" fullword ascii /* score: '1.00'*/
      $s40 = "%~FL6Q(" fullword ascii /* score: '1.00'*/
      $s41 = "-hm=\"\\0+" fullword ascii /* score: '1.00'*/
      $s42 = "gm]GA." fullword ascii /* score: '1.00'*/
      $s43 = "ZUpo;:" fullword ascii /* score: '1.00'*/
      $s44 = "@}p *YvF" fullword ascii /* score: '1.00'*/
      $s45 = ".Fj$i|L" fullword ascii /* score: '1.00'*/
      $s46 = "cZG]aN" fullword ascii /* score: '1.00'*/
      $s47 = "=u@MbaWI`" fullword ascii /* score: '1.00'*/
      $s48 = "<G)DeA5%" fullword ascii /* score: '1.00'*/
      $s49 = "n{y)}D" fullword ascii /* score: '1.00'*/
      $s50 = "-1^)PN" fullword ascii /* score: '1.00'*/
      $s51 = "OB$L9f" fullword ascii /* score: '1.00'*/
      $s52 = "L}Cf7F" fullword ascii /* score: '1.00'*/
      $s53 = "}u$aYgR" fullword ascii /* score: '1.00'*/
      $s54 = "!yLcPar" fullword ascii /* score: '1.00'*/
      $s55 = "g<Wn4n" fullword ascii /* score: '1.00'*/
      $s56 = "VDY,7cI" fullword ascii /* score: '1.00'*/
      $s57 = ":.1n`T" fullword ascii /* score: '1.00'*/
      $s58 = "R*TNIK" fullword ascii /* score: '1.00'*/
      $s59 = "j]=_.-" fullword ascii /* score: '1.00'*/
      $s60 = ".#N.@o" fullword ascii /* score: '1.00'*/
      $s61 = ":'go|2" fullword ascii /* score: '1.00'*/
      $s62 = "R7aCCj" fullword ascii /* score: '1.00'*/
      $s63 = "]6&rG3" fullword ascii /* score: '1.00'*/
      $s64 = "3(z2|{Fk" fullword ascii /* score: '1.00'*/
      $s65 = " 7&787" fullword ascii /* score: '1.00'*/
      $s66 = "^Ya'C)O" fullword ascii /* score: '1.00'*/
      $s67 = "/h*!Ev+" fullword ascii /* score: '1.00'*/
      $s68 = ",NYffp" fullword ascii /* score: '1.00'*/
      $s69 = "d#o:F!" fullword ascii /* score: '1.00'*/
      $s70 = "l5,38!" fullword ascii /* score: '1.00'*/
      $s71 = "O8Tg-," fullword ascii /* score: '1.00'*/
      $s72 = "y?{Yp?" fullword ascii /* score: '1.00'*/
      $s73 = "R}T^~H" fullword ascii /* score: '1.00'*/
      $s74 = "Sa?fY]F" fullword ascii /* score: '1.00'*/
      $s75 = "x75o<@" fullword ascii /* score: '1.00'*/
      $s76 = "y9NPL4" fullword ascii /* score: '1.00'*/
      $s77 = "A05_!Nb" fullword ascii /* score: '1.00'*/
      $s78 = "?NZY&p" fullword ascii /* score: '1.00'*/
      $s79 = "g|e'hF" fullword ascii /* score: '1.00'*/
      $s80 = "OIVt0T" fullword ascii /* score: '1.00'*/
      $s81 = "J,6[+`t" fullword ascii /* score: '1.00'*/
      $s82 = "N/hP'Sp" fullword ascii /* score: '1.00'*/
      $s83 = "2YVA.#+" fullword ascii /* score: '1.00'*/
      $s84 = "w7_Orx" fullword ascii /* score: '1.00'*/
      $s85 = "j+{g?z" fullword ascii /* score: '1.00'*/
      $s86 = "+vJhZl" fullword ascii /* score: '1.00'*/
      $s87 = "`W](CW" fullword ascii /* score: '1.00'*/
      $s88 = "VC`wC>" fullword ascii /* score: '1.00'*/
      $s89 = "xgEFy+" fullword ascii /* score: '1.00'*/
      $s90 = "ypn4$3wV" fullword ascii /* score: '1.00'*/
      $s91 = "}^8ZM0" fullword ascii /* score: '1.00'*/
      $s92 = "c6R4O#;h" fullword ascii /* score: '1.00'*/
      $s93 = "{qy^1r" fullword ascii /* score: '1.00'*/
      $s94 = "&QBVPp" fullword ascii /* score: '1.00'*/
      $s95 = "G@Jzr\\" fullword ascii /* score: '1.00'*/
      $s96 = "VpA<dT6" fullword ascii /* score: '1.00'*/
      $s97 = "a.mexI" fullword ascii /* score: '1.00'*/
      $s98 = "M7Vh]H" fullword ascii /* score: '1.00'*/
      $s99 = ",4vgc?" fullword ascii /* score: '1.00'*/
      $s100 = ")$UH4H" fullword ascii /* score: '1.00'*/
      $s101 = "T(XcCI" fullword ascii /* score: '1.00'*/
      $s102 = "*YAS5`g" fullword ascii /* score: '1.00'*/
      $s103 = "BE\\)4w" fullword ascii /* score: '1.00'*/
      $s104 = "[]q&Q9" fullword ascii /* score: '1.00'*/
      $s105 = "y_`bK<" fullword ascii /* score: '1.00'*/
      $s106 = "hhKMkh" fullword ascii /* score: '1.00'*/
      $s107 = "EA+[!k{L" fullword ascii /* score: '1.00'*/
      $s108 = "8hwq?8X" fullword ascii /* score: '1.00'*/
      $s109 = "jNnP3N" fullword ascii /* score: '1.00'*/
      $s110 = "pH\\}T9" fullword ascii /* score: '1.00'*/
      $s111 = "Oxt^!R" fullword ascii /* score: '1.00'*/
      $s112 = "32[[wt" fullword ascii /* score: '1.00'*/
      $s113 = "$#\"ljq" fullword ascii /* score: '1.00'*/
      $s114 = "O=iY;n" fullword ascii /* score: '1.00'*/
      $s115 = "jZWcf%" fullword ascii /* score: '1.00'*/
      $s116 = "N.H-rG" fullword ascii /* score: '1.00'*/
      $s117 = "%1YW2Fk" fullword ascii /* score: '1.00'*/
      $s118 = "C\\,,BCc" fullword ascii /* score: '1.00'*/
      $s119 = "V\"rOa9bi" fullword ascii /* score: '1.00'*/
      $s120 = "U)f~JK" fullword ascii /* score: '1.00'*/
      $s121 = "Ykm(t/$" fullword ascii /* score: '1.00'*/
      $s122 = "VyLF&|" fullword ascii /* score: '1.00'*/
      $s123 = "Ud7uMl" fullword ascii /* score: '1.00'*/
      $s124 = "@X0'rm" fullword ascii /* score: '1.00'*/
      $s125 = "%zX]J|" fullword ascii /* score: '1.00'*/
      $s126 = "j<oe=u" fullword ascii /* score: '1.00'*/
      $s127 = "01\\'we" fullword ascii /* score: '1.00'*/
      $s128 = "rK4;;RRD" fullword ascii /* score: '1.00'*/
      $s129 = "3vPKKD" fullword ascii /* score: '1.00'*/
      $s130 = "B{-s,." fullword ascii /* score: '1.00'*/
      $s131 = "%E9AF5)" fullword ascii /* score: '1.00'*/
      $s132 = "-fI\"'F" fullword ascii /* score: '1.00'*/
      $s133 = "i0idCn" fullword ascii /* score: '1.00'*/
      $s134 = "3-P6'x <+" fullword ascii /* score: '1.00'*/
      $s135 = "`kZ-M/xFWMs" fullword ascii /* score: '1.00'*/
      $s136 = ".#gN\"J" fullword ascii /* score: '1.00'*/
      $s137 = "~,`]^k" fullword ascii /* score: '1.00'*/
      $s138 = "X6P#K9" fullword ascii /* score: '1.00'*/
      $s139 = "SG?1Qn" fullword ascii /* score: '1.00'*/
      $s140 = "ho'h:_4" fullword ascii /* score: '1.00'*/
      $s141 = "I9gR1%yz" fullword ascii /* score: '1.00'*/
      $s142 = "+*.!TnS" fullword ascii /* score: '1.00'*/
      $s143 = "|'nmy#" fullword ascii /* score: '1.00'*/
      $s144 = "nV}T <" fullword ascii /* score: '1.00'*/
      $s145 = "5j`L-(" fullword ascii /* score: '1.00'*/
      $s146 = ":k`?^r2" fullword ascii /* score: '1.00'*/
      $s147 = "sD$lVr" fullword ascii /* score: '1.00'*/
      $s148 = "$_:;:@" fullword ascii /* score: '1.00'*/
      $s149 = "/9+Gd[" fullword ascii /* score: '1.00'*/
      $s150 = "(km/Mx" fullword ascii /* score: '1.00'*/
      $s151 = "!W?fBM" fullword ascii /* score: '1.00'*/
      $s152 = "cVw6K<" fullword ascii /* score: '1.00'*/
      $s153 = ":-<#%C6y" fullword ascii /* score: '1.00'*/
      $s154 = "MNi[mR" fullword ascii /* score: '1.00'*/
      $s155 = "7sD9#%F\"" fullword ascii /* score: '1.00'*/
      $s156 = "Xx?/\"x" fullword ascii /* score: '1.00'*/
      $s157 = "$Tgv9Y" fullword ascii /* score: '1.00'*/
      $s158 = "DGn>/3" fullword ascii /* score: '1.00'*/
      $s159 = "\"Q6#7\"X" fullword ascii /* score: '1.00'*/
      $s160 = "_T)QRnTL" fullword ascii /* score: '1.00'*/
      $s161 = "&uJxna" fullword ascii /* score: '1.00'*/
      $s162 = "{acr~_;2Bf" fullword ascii /* score: '1.00'*/
      $s163 = "x71r}\"" fullword ascii /* score: '1.00'*/
      $s164 = "BCZ5Nsg" fullword ascii /* score: '1.00'*/
      $s165 = "vO_>cOT0)" fullword ascii /* score: '1.00'*/
      $s166 = "(*nL6#" fullword ascii /* score: '1.00'*/
      $s167 = ":\\L%oh" fullword ascii /* score: '1.00'*/
      $s168 = "Bs=y\\Q" fullword ascii /* score: '1.00'*/
      $s169 = "&ZBS)7" fullword ascii /* score: '1.00'*/
      $s170 = "@9WQIJ" fullword ascii /* score: '1.00'*/
      $s171 = "^|,BR; " fullword ascii /* score: '1.00'*/
      $s172 = "UR OA>R" fullword ascii /* score: '1.00'*/
      $s173 = "0d89Ek" fullword ascii /* score: '1.00'*/
      $s174 = "FJ}Fpz" fullword ascii /* score: '1.00'*/
      $s175 = "s7s=,P1r" fullword ascii /* score: '1.00'*/
      $s176 = "t|-Fag" fullword ascii /* score: '1.00'*/
      $s177 = "+j0}.x" fullword ascii /* score: '1.00'*/
      $s178 = "pHF$ux" fullword ascii /* score: '1.00'*/
      $s179 = "$}D~NX" fullword ascii /* score: '1.00'*/
      $s180 = "}(fdP0To" fullword ascii /* score: '1.00'*/
      $s181 = "h5`0>l" fullword ascii /* score: '1.00'*/
      $s182 = "@BUS~%" fullword ascii /* score: '1.00'*/
      $s183 = "LrdB7`" fullword ascii /* score: '1.00'*/
      $s184 = "PS\\efB" fullword ascii /* score: '1.00'*/
      $s185 = ",H3RG(" fullword ascii /* score: '1.00'*/
      $s186 = "eKxxfq" fullword ascii /* score: '1.00'*/
      $s187 = "kKT~U]" fullword ascii /* score: '1.00'*/
      $s188 = "Ciz*>}" fullword ascii /* score: '1.00'*/
      $s189 = ".*C(hV" fullword ascii /* score: '1.00'*/
      $s190 = "7<|<kK" fullword ascii /* score: '1.00'*/
      $s191 = "!7FCtT" fullword ascii /* score: '1.00'*/
      $s192 = "'4PV2{!" fullword ascii /* score: '1.00'*/
      $s193 = " )Y'WR" fullword ascii /* score: '1.00'*/
      $s194 = "\"{bPL|" fullword ascii /* score: '1.00'*/
      $s195 = "=;Eb[bp" fullword ascii /* score: '1.00'*/
      $s196 = "9Ds\\{2" fullword ascii /* score: '1.00'*/
      $s197 = "3G@u>v%" fullword ascii /* score: '1.00'*/
      $s198 = "!K*9><" fullword ascii /* score: '1.00'*/
      $s199 = "L$,~QUgz" fullword ascii /* score: '1.00'*/
      $s200 = "zs5&(OB" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "1efe015ade03f54dd6d9b2ccea28b970" and ( 8 of them )
      ) or ( all of them )
}

rule _707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6_2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc_4 {
   meta:
      description = "Amadey_MALW - from files 707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6, 2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6"
      hash2 = "2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
   strings:
      $s1 = "O -rf&" fullword ascii /* score: '5.00'*/
      $s2 = "5.IEv," fullword ascii /* score: '4.00'*/
      $s3 = "AhrHKq!Rj" fullword ascii /* score: '4.00'*/
      $s4 = "uuhJK0a" fullword ascii /* score: '4.00'*/
      $s5 = "FsgJ7=." fullword ascii /* score: '4.00'*/
      $s6 = "cTOw]TZ" fullword ascii /* score: '4.00'*/
      $s7 = "ISxq8t@" fullword ascii /* score: '4.00'*/
      $s8 = "kxbkuHZW" fullword ascii /* score: '4.00'*/
      $s9 = "xDQFgSA" fullword ascii /* score: '4.00'*/
      $s10 = "MpXIQsj" fullword ascii /* score: '4.00'*/
      $s11 = "\"?lMBz}h*" fullword ascii /* score: '4.00'*/
      $s12 = "JuYUI0" fullword ascii /* score: '2.00'*/
      $s13 = "\\cwp>i}" fullword ascii /* score: '2.00'*/
      $s14 = "Xkd:%." fullword ascii /* score: '1.00'*/
      $s15 = "8V)R^L" fullword ascii /* score: '1.00'*/
      $s16 = "v>p0Rm8f" fullword ascii /* score: '1.00'*/
      $s17 = "i?['!K" fullword ascii /* score: '1.00'*/
      $s18 = "i5T>\"|N" fullword ascii /* score: '1.00'*/
      $s19 = "u4\\$k9C}@" fullword ascii /* score: '1.00'*/
      $s20 = "R/dt,D" fullword ascii /* score: '1.00'*/
      $s21 = "?tsk!A" fullword ascii /* score: '1.00'*/
      $s22 = "y~y5O_" fullword ascii /* score: '1.00'*/
      $s23 = "6bQQCc" fullword ascii /* score: '1.00'*/
      $s24 = "f0A{%_" fullword ascii /* score: '1.00'*/
      $s25 = "t]^3Xjw" fullword ascii /* score: '1.00'*/
      $s26 = "b@LqAs0" fullword ascii /* score: '1.00'*/
      $s27 = "{'iL/c" fullword ascii /* score: '1.00'*/
      $s28 = "=:V{Zg[" fullword ascii /* score: '1.00'*/
      $s29 = "G-zn}k" fullword ascii /* score: '1.00'*/
      $s30 = "9_bW7S" fullword ascii /* score: '1.00'*/
      $s31 = "<V@edR[a']" fullword ascii /* score: '1.00'*/
      $s32 = "%YgD_R" fullword ascii /* score: '1.00'*/
      $s33 = "w#|qg^" fullword ascii /* score: '1.00'*/
      $s34 = "|[QmX&" fullword ascii /* score: '1.00'*/
      $s35 = "z}\")Sb" fullword ascii /* score: '1.00'*/
      $s36 = "Ox&O{#" fullword ascii /* score: '1.00'*/
      $s37 = "{Rs*C&GjN" fullword ascii /* score: '1.00'*/
      $s38 = "x5t(bi8" fullword ascii /* score: '1.00'*/
      $s39 = "1F?Sl7" fullword ascii /* score: '1.00'*/
      $s40 = "!xd'=p" fullword ascii /* score: '1.00'*/
      $s41 = "W$J%N+x" fullword ascii /* score: '1.00'*/
      $s42 = "E->,9E" fullword ascii /* score: '1.00'*/
      $s43 = "_zk.k@" fullword ascii /* score: '1.00'*/
      $s44 = "!9j1Yw" fullword ascii /* score: '1.00'*/
      $s45 = "p$,y[*m7P" fullword ascii /* score: '1.00'*/
      $s46 = "%/zRFf" fullword ascii /* score: '1.00'*/
      $s47 = "sk_ocX" fullword ascii /* score: '1.00'*/
      $s48 = "]hiXTt" fullword ascii /* score: '1.00'*/
      $s49 = "W4O7. " fullword ascii /* score: '1.00'*/
      $s50 = "!#19cL\\5" fullword ascii /* score: '1.00'*/
      $s51 = "pfY%$&m" fullword ascii /* score: '1.00'*/
      $s52 = "CXP0j-" fullword ascii /* score: '1.00'*/
      $s53 = "6[#_Tu" fullword ascii /* score: '1.00'*/
      $s54 = "P`rfpt" fullword ascii /* score: '1.00'*/
      $s55 = "a7d,DU" fullword ascii /* score: '1.00'*/
      $s56 = "#Ba}g??'" fullword ascii /* score: '1.00'*/
      $s57 = "Z_dy:r" fullword ascii /* score: '1.00'*/
      $s58 = "&U@)Ke" fullword ascii /* score: '1.00'*/
      $s59 = "gv6l)R" fullword ascii /* score: '1.00'*/
      $s60 = "bM.Vc=D" fullword ascii /* score: '1.00'*/
      $s61 = "rU&g_xT" fullword ascii /* score: '1.00'*/
      $s62 = " 'k7'$" fullword ascii /* score: '1.00'*/
      $s63 = "S5%+F]%" fullword ascii /* score: '1.00'*/
      $s64 = "y&D_>n" fullword ascii /* score: '1.00'*/
      $s65 = "EZ<3L\"" fullword ascii /* score: '1.00'*/
      $s66 = "^Dx~$(" fullword ascii /* score: '1.00'*/
      $s67 = "YAc8$'j;" fullword ascii /* score: '1.00'*/
      $s68 = "L1(QeQ('(" fullword ascii /* score: '1.00'*/
      $s69 = "Z+a-mcRF" fullword ascii /* score: '1.00'*/
      $s70 = "onJ@GF" fullword ascii /* score: '1.00'*/
      $s71 = "^dR.~G" fullword ascii /* score: '1.00'*/
      $s72 = "lvd!VKN@s0cM" fullword ascii /* score: '1.00'*/
      $s73 = "zH>1Fq." fullword ascii /* score: '1.00'*/
      $s74 = "V\\}_]kY" fullword ascii /* score: '1.00'*/
      $s75 = "vs23{#A" fullword ascii /* score: '1.00'*/
      $s76 = "!nu6.uD" fullword ascii /* score: '1.00'*/
      $s77 = "tFrB<2" fullword ascii /* score: '1.00'*/
      $s78 = "B[1s25$" fullword ascii /* score: '1.00'*/
      $s79 = "|GLK*[" fullword ascii /* score: '1.00'*/
      $s80 = "/a.D8m" fullword ascii /* score: '1.00'*/
      $s81 = "_@x7)^" fullword ascii /* score: '1.00'*/
      $s82 = "!g)nzt" fullword ascii /* score: '1.00'*/
      $s83 = "~dASx5" fullword ascii /* score: '1.00'*/
      $s84 = "pCS\" ." fullword ascii /* score: '1.00'*/
      $s85 = "CJ;GG*k" fullword ascii /* score: '1.00'*/
      $s86 = "IJ[x;M" fullword ascii /* score: '1.00'*/
      $s87 = "1-/\\tc" fullword ascii /* score: '1.00'*/
      $s88 = "IY/QAh" fullword ascii /* score: '1.00'*/
      $s89 = "pdr%F]" fullword ascii /* score: '1.00'*/
      $s90 = "ugd/gp" fullword ascii /* score: '1.00'*/
      $s91 = "z(bkOo" fullword ascii /* score: '1.00'*/
      $s92 = "S:^<Wt" fullword ascii /* score: '1.00'*/
      $s93 = "4J1aid" fullword ascii /* score: '1.00'*/
      $s94 = "#1$8Ef" fullword ascii /* score: '1.00'*/
      $s95 = ";Kw0>d" fullword ascii /* score: '1.00'*/
      $s96 = "$){H\\m" fullword ascii /* score: '1.00'*/
      $s97 = "?y0K7!=I" fullword ascii /* score: '1.00'*/
      $s98 = "{(NFg{" fullword ascii /* score: '1.00'*/
      $s99 = "h2QtlI" fullword ascii /* score: '1.00'*/
      $s100 = "_x9m%7VP" fullword ascii /* score: '1.00'*/
      $s101 = "i4Ou'=lh" fullword ascii /* score: '1.00'*/
      $s102 = "]us^_[Y" fullword ascii /* score: '1.00'*/
      $s103 = "R4b%Jk" fullword ascii /* score: '1.00'*/
      $s104 = "VfVXeH" fullword ascii /* score: '1.00'*/
      $s105 = "_1lY<v" fullword ascii /* score: '1.00'*/
      $s106 = " 9{#Ul" fullword ascii /* score: '1.00'*/
      $s107 = "G'42+@" fullword ascii /* score: '1.00'*/
      $s108 = "+Q7COb" fullword ascii /* score: '1.00'*/
      $s109 = "ZP!f[+C" fullword ascii /* score: '1.00'*/
      $s110 = ">f|+?jt;" fullword ascii /* score: '1.00'*/
      $s111 = ":(LwBy4" fullword ascii /* score: '1.00'*/
      $s112 = "}Gp~1XI" fullword ascii /* score: '1.00'*/
      $s113 = ")HN^f&o" fullword ascii /* score: '1.00'*/
      $s114 = ")jspUu" fullword ascii /* score: '1.00'*/
      $s115 = "2c[/,7" fullword ascii /* score: '1.00'*/
      $s116 = "o4< he" fullword ascii /* score: '1.00'*/
      $s117 = "*'xfL>" fullword ascii /* score: '1.00'*/
      $s118 = "&v1V9M" fullword ascii /* score: '1.00'*/
      $s119 = "kY`ws5&" fullword ascii /* score: '1.00'*/
      $s120 = "RC0aKK$" fullword ascii /* score: '1.00'*/
      $s121 = "M@>dzc" fullword ascii /* score: '1.00'*/
      $s122 = "n}fMrO" fullword ascii /* score: '1.00'*/
      $s123 = "2VYsuu%" fullword ascii /* score: '1.00'*/
      $s124 = "rF4=zz," fullword ascii /* score: '1.00'*/
      $s125 = "nWV#Cz9" fullword ascii /* score: '1.00'*/
      $s126 = "Fg&Ap'" fullword ascii /* score: '1.00'*/
      $s127 = "3O>RFF" fullword ascii /* score: '1.00'*/
      $s128 = "^_HM2t" fullword ascii /* score: '1.00'*/
      $s129 = "dP}N+!{" fullword ascii /* score: '1.00'*/
      $s130 = "(EcB\"fq" fullword ascii /* score: '1.00'*/
      $s131 = "{D\"fL-" fullword ascii /* score: '1.00'*/
      $s132 = "CNU(Kb" fullword ascii /* score: '1.00'*/
      $s133 = "V[-KA1" fullword ascii /* score: '1.00'*/
      $s134 = "( ^^mh" fullword ascii /* score: '1.00'*/
      $s135 = "Y[D>Bh" fullword ascii /* score: '1.00'*/
      $s136 = "ekP}~1" fullword ascii /* score: '1.00'*/
      $s137 = "bS?'n0" fullword ascii /* score: '1.00'*/
      $s138 = "k|17Nd" fullword ascii /* score: '1.00'*/
      $s139 = "0Aq\"|S" fullword ascii /* score: '1.00'*/
      $s140 = "G8Z1{P" fullword ascii /* score: '1.00'*/
      $s141 = "2>/8YsF_" fullword ascii /* score: '1.00'*/
      $s142 = "fZjf(f" fullword ascii /* score: '1.00'*/
      $s143 = "rYI:yA" fullword ascii /* score: '1.00'*/
      $s144 = "2ODu>u" fullword ascii /* score: '1.00'*/
      $s145 = "r&[6!\"" fullword ascii /* score: '1.00'*/
      $s146 = "[9HFb7" fullword ascii /* score: '1.00'*/
      $s147 = ":3XZlq{" fullword ascii /* score: '1.00'*/
      $s148 = "44ph`1K" fullword ascii /* score: '1.00'*/
      $s149 = "mpk>^9C" fullword ascii /* score: '1.00'*/
      $s150 = "s|wj;/" fullword ascii /* score: '1.00'*/
      $s151 = "}H].!5Y" fullword ascii /* score: '1.00'*/
      $s152 = "Y'e]2\\" fullword ascii /* score: '1.00'*/
      $s153 = ";Ee\\Nz8" fullword ascii /* score: '1.00'*/
      $s154 = "rmu>5AxOmY" fullword ascii /* score: '1.00'*/
      $s155 = "[oQF2ol" fullword ascii /* score: '1.00'*/
      $s156 = "AFOm[V" fullword ascii /* score: '1.00'*/
      $s157 = "/M%f=3" fullword ascii /* score: '1.00'*/
      $s158 = "MhtMQc" fullword ascii /* score: '1.00'*/
      $s159 = "NJ|H[%" fullword ascii /* score: '1.00'*/
      $s160 = "3K6QTh" fullword ascii /* score: '1.00'*/
      $s161 = "u9vuIY&" fullword ascii /* score: '1.00'*/
      $s162 = "dEE5X}" fullword ascii /* score: '1.00'*/
      $s163 = "w+Eh^7j" fullword ascii /* score: '1.00'*/
      $s164 = "=a1w\"n" fullword ascii /* score: '1.00'*/
      $s165 = "d7^K$o" fullword ascii /* score: '1.00'*/
      $s166 = "#`:\"3Q" fullword ascii /* score: '1.00'*/
      $s167 = "jM)o}Z" fullword ascii /* score: '1.00'*/
      $s168 = "0jLzn0c" fullword ascii /* score: '1.00'*/
      $s169 = "X/@r6%Lqz" fullword ascii /* score: '1.00'*/
      $s170 = "F/_`1b" fullword ascii /* score: '1.00'*/
      $s171 = "|AZx.X?" fullword ascii /* score: '1.00'*/
      $s172 = "H)*58(?d" fullword ascii /* score: '1.00'*/
      $s173 = ".>9J6F" fullword ascii /* score: '1.00'*/
      $s174 = "q\\5.m1s" fullword ascii /* score: '1.00'*/
      $s175 = "J0@E55" fullword ascii /* score: '1.00'*/
      $s176 = "s:LCS+T1" fullword ascii /* score: '1.00'*/
      $s177 = "+m+`Y3R^" fullword ascii /* score: '1.00'*/
      $s178 = "c]$pc*P" fullword ascii /* score: '1.00'*/
      $s179 = "n359`{" fullword ascii /* score: '1.00'*/
      $s180 = "cOo\\w p" fullword ascii /* score: '1.00'*/
      $s181 = "Y~WER4s" fullword ascii /* score: '1.00'*/
      $s182 = " IM=''" fullword ascii /* score: '1.00'*/
      $s183 = ";2K#Xm" fullword ascii /* score: '1.00'*/
      $s184 = "|z$OHd" fullword ascii /* score: '1.00'*/
      $s185 = "aMh?Vs" fullword ascii /* score: '1.00'*/
      $s186 = "B}<]bO" fullword ascii /* score: '1.00'*/
      $s187 = "mtY(y#" fullword ascii /* score: '1.00'*/
      $s188 = "{rN<9\"" fullword ascii /* score: '1.00'*/
      $s189 = "#2`yWtB" fullword ascii /* score: '1.00'*/
      $s190 = "_ld%u`~" fullword ascii /* score: '1.00'*/
      $s191 = "_W $vD" fullword ascii /* score: '1.00'*/
      $s192 = " cK_4," fullword ascii /* score: '1.00'*/
      $s193 = "u(SUq{h" fullword ascii /* score: '1.00'*/
      $s194 = ";.m[^K" fullword ascii /* score: '1.00'*/
      $s195 = "'S'cp[M" fullword ascii /* score: '1.00'*/
      $s196 = "Cx0sUA" fullword ascii /* score: '1.00'*/
      $s197 = "B4cRs+" fullword ascii /* score: '1.00'*/
      $s198 = "DiQ#,fv" fullword ascii /* score: '1.00'*/
      $s199 = "P_Q >W~(" fullword ascii /* score: '1.00'*/
      $s200 = "'|&k+l" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "1efe015ade03f54dd6d9b2ccea28b970" and ( 8 of them )
      ) or ( all of them )
}

rule _b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65_12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d_5 {
   meta:
      description = "Amadey_MALW - from files b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65, 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1, 488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77, 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c, 919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226, ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65"
      hash2 = "12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
      hash3 = "488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
      hash4 = "5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
      hash5 = "919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
      hash6 = "ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s2 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s3 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s5 = "WWWSHSh" fullword ascii /* score: '4.00'*/
      $s6 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s7 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s8 = "WPWWWS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s10 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "D8(Ht'" fullword ascii /* score: '1.00'*/
      $s12 = "u kE$<" fullword ascii /* score: '1.00'*/
      $s13 = ":u\"f9z" fullword ascii /* score: '1.00'*/
      $s14 = "UTF-16LEUNICODE" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s15 = "CM @PRj" fullword ascii /* score: '1.00'*/
      $s16 = "<=upG8" fullword ascii /* score: '1.00'*/
      $s17 = "zSSSSj" fullword ascii /* score: '1.00'*/
      $s18 = "<at.<rt!<wt" fullword ascii /* score: '1.00'*/
      $s19 = "api-ms-" fullword wide /* score: '1.00'*/
      $s20 = "ext-ms-" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1_919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c_6 {
   meta:
      description = "Amadey_MALW - from files 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1, 919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
      hash2 = "919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
   strings:
      $s1 = ":$:,:0:8:L:T:\\:h:" fullword ascii /* score: '7.00'*/
      $s2 = "?$?4?8?L?P?`?d?h?p?" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "728?8M8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "6$686@6H6T6t6|6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "4$444@4`4h4p4x4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "1 1$14181H1L1\\1`1d1l1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "50585@5" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "8p9V:h:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s9 = "?0?K?c?" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "4 4(4,40484L4T4X4`4t4|4" fullword ascii /* score: '1.00'*/
      $s11 = "3V3a3F4U4" fullword ascii /* score: '1.00'*/
      $s12 = "=&?7?}?" fullword ascii /* score: '1.00'*/
      $s13 = "6 606@6D6T6X6\\6p6t6x6" fullword ascii /* score: '1.00'*/
      $s14 = "141<1D1L1|1" fullword ascii /* score: '1.00'*/
      $s15 = "060T0Z0" fullword ascii /* score: '1.00'*/
      $s16 = "5$585H5l5x5" fullword ascii /* score: '1.00'*/
      $s17 = "5'6I6_6" fullword ascii /* score: '1.00'*/
      $s18 = "6Y6@7O7" fullword ascii /* score: '1.00'*/
      $s19 = "585@5H5P5X5`5h5x5" fullword ascii /* score: '1.00'*/
      $s20 = "6$6+656?6F6P6Z6e6" fullword ascii /* score: '1.00'*/
      $s21 = "3%4D4[4" fullword ascii /* score: '1.00'*/
      $s22 = "f95TcF" fullword ascii /* score: '1.00'*/
      $s23 = "=<=D=L=T=\\=d=l=x=" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s24 = "8 848D8T8X8\\8t8" fullword ascii /* score: '1.00'*/
      $s25 = "7$7-7>7" fullword ascii /* score: '1.00'*/
      $s26 = "4,5054585P5T5d5h5l5t5" fullword ascii /* score: '1.00'*/
      $s27 = "1!13181B1Q1c1m1" fullword ascii /* score: '1.00'*/
      $s28 = "=&=F=S=" fullword ascii /* score: '1.00'*/
      $s29 = "7(7,707D7H7X7\\7t7x7" fullword ascii /* score: '1.00'*/
      $s30 = "=@=H=P=`=l=t=" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s31 = "5 5$5054585<5@5D5H5L5`5d5h5l5" fullword ascii /* score: '1.00'*/
      $s32 = "=6>F>t>" fullword ascii /* score: '1.00'*/
      $s33 = "0A1Z1l1" fullword ascii /* score: '1.00'*/
      $s34 = "0 0$0,0D0T0X0h0x0|0" fullword ascii /* score: '1.00'*/
      $s35 = "<0<V<e<" fullword ascii /* score: '1.00'*/
      $s36 = "9I9N9T9\\9e9m9" fullword ascii /* score: '1.00'*/
      $s37 = "<#<b<I=X=" fullword ascii /* score: '1.00'*/
      $s38 = "8.868Q8]8i8z8" fullword ascii /* score: '1.00'*/
      $s39 = "? ?$?(?,?D?" fullword ascii /* score: '1.00'*/
      $s40 = "060L0k0" fullword ascii /* score: '1.00'*/
      $s41 = "?@?L?T?|?" fullword ascii /* score: '1.00'*/
      $s42 = "4,4044484<4D4H4\\4`4h4l4t4|4" fullword ascii /* score: '1.00'*/
      $s43 = "< <$<4<8<<<@<D<L<d<h<" fullword ascii /* score: '1.00'*/
      $s44 = "5,50545L5P5h5l5p5x5" fullword ascii /* score: '1.00'*/
      $s45 = "6+7F7W7" fullword ascii /* score: '1.00'*/
      $s46 = "0-1F1a1y1" fullword ascii /* score: '1.00'*/
      $s47 = ";B;b;n;v;" fullword ascii /* score: '1.00'*/
      $s48 = "Rich3%" fullword ascii /* score: '1.00'*/
      $s49 = "3 3(30383D3L3l3|3" fullword ascii /* score: '1.00'*/
      $s50 = "5$5,5D5X5`5h5p5x5" fullword ascii /* score: '1.00'*/
      $s51 = "?,?<?@?P?T?X?p?" fullword ascii /* score: '1.00'*/
      $s52 = "8(8,8D8T8X8l8p8" fullword ascii /* score: '1.00'*/
      $s53 = ";$;(;0;D;L;X;" fullword ascii /* score: '1.00'*/
      $s54 = "=$=D=L=T=X=`=t=|=" fullword ascii /* score: '1.00'*/
      $s55 = "4>5l5x5W6" fullword ascii /* score: '1.00'*/
      $s56 = "6w6i7y7" fullword ascii /* score: '1.00'*/
      $s57 = "4,444<4D4T4\\4l4|4" fullword ascii /* score: '1.00'*/
      $s58 = "1 181<1@1H1`1p1t1x1" fullword ascii /* score: '1.00'*/
      $s59 = "3,30343H3L3P3h3l3" fullword ascii /* score: '1.00'*/
      $s60 = "2,202@2D2\\2l2|2" fullword ascii /* score: '1.00'*/
      $s61 = ":,:4:@:`:h:p:t:x:" fullword ascii /* score: '1.00'*/
      $s62 = "5$5(5,505A5j5o5v5}5" fullword ascii /* score: '1.00'*/
      $s63 = ">$>(>0>8>@>D>H>P>d>l>" fullword ascii /* score: '1.00'*/
      $s64 = "2%212;2G2[2f2l2r213" fullword ascii /* score: '1.00'*/
      $s65 = "DEjjjj" fullword wide /* score: '1.00'*/
      $s66 = "9(9T9x9" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s67 = "6,6<6@6D6L6d6t6x6" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s68 = "7 7@7L7t7" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "d0db1addc5d20c6bf2731d82832030a0" and ( 8 of them )
      ) or ( all of them )
}

rule _5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c_ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b_7 {
   meta:
      description = "Amadey_MALW - from files 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c, ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
      hash2 = "ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
   strings:
      $s1 = "0 0$0(0,000X0\\0`0d0h0l0p0t0x0|0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "=$=(=@=P=T=h=l=|=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "0T1X1`1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "6 6(6@6D6\\6l6p6t6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "> >$>(>,>@>D>T>X>h>l>p>x>" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "4 484<4T4d4h4|4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "30484@4H4P4X4`4h4p4x4" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "006700e5a2ab05704bbb0c589b88924d" ascii /* score: '3.00'*/
      $s9 = "6$6<6L6P6X6p6" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = ">$>(>8><>@>H>`>d>|>" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = ":$:(:,:4:L:\\:`:h:" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "3 30343L3P3T3h3x3|3" fullword ascii /* score: '1.00'*/
      $s13 = "=%=M=W=r=~=" fullword ascii /* score: '1.00'*/
      $s14 = "5 5,5054585<5@5D5H5\\5`5d5h5" fullword ascii /* score: '1.00'*/
      $s15 = "4'5I5_5" fullword ascii /* score: '1.00'*/
      $s16 = "5Y6i6}8" fullword ascii /* score: '1.00'*/
      $s17 = "1$1(1@1D1H1\\1l1|1" fullword ascii /* score: '1.00'*/
      $s18 = "f958cF" ascii /* score: '1.00'*/
      $s19 = ":&;5;f<x<" fullword ascii /* score: '1.00'*/
      $s20 = "2%3D3[3" fullword ascii /* score: '1.00'*/
      $s21 = "?@?T?\\?d?l?t?" fullword ascii /* score: '1.00'*/
      $s22 = "2 2$2(2,2@2P2T2l2p2t2|2" fullword ascii /* score: '1.00'*/
      $s23 = "5w5V6e6" fullword ascii /* score: '1.00'*/
      $s24 = "1(2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t287<7@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7" fullword ascii /* score: '1.00'*/
      $s25 = "4,40444<4T4d4t4x4" fullword ascii /* score: '1.00'*/
      $s26 = "<&<F<S<" fullword ascii /* score: '1.00'*/
      $s27 = ":6:<:C:" fullword ascii /* score: '1.00'*/
      $s28 = "= =0=4=8=P=T=l=p=t=x=" fullword ascii /* score: '1.00'*/
      $s29 = "0,0004080@0T0X0h0x0|0" fullword ascii /* score: '1.00'*/
      $s30 = "?,?<?@?P?T?l?|?" fullword ascii /* score: '1.00'*/
      $s31 = "<$<<<@<D<H<P<T<X<\\<d<|<" fullword ascii /* score: '1.00'*/
      $s32 = ";0;V;e;" fullword ascii /* score: '1.00'*/
      $s33 = "xi;50bF" fullword ascii /* score: '1.00'*/
      $s34 = ":&:G:N:" fullword ascii /* score: '1.00'*/
      $s35 = "7 7$7(7,7074787<7@7D7P7T7X7p7t7x7" fullword ascii /* score: '1.00'*/
      $s36 = "=%>S>\\>6?L?e?" fullword ascii /* score: '1.00'*/
      $s37 = "u\"hhZF" fullword ascii /* score: '1.00'*/
      $s38 = "4$4(4,404A4j4o4v4}4" fullword ascii /* score: '1.00'*/
      $s39 = "4 4)4/4G4Q4c4v4" fullword ascii /* score: '1.00'*/
      $s40 = "74787<7@7D7H7L7" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s41 = "3 3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3t3x3|3" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s42 = "e5a2ab05704bbb0c589b88924d" ascii /* score: '1.00'*/
      $s43 = "1%111;1G1[1f1l1r112" fullword ascii /* score: '1.00'*/
      $s44 = "8#8+8D8I8#9*9f9x9" fullword ascii /* score: '1.00'*/
      $s45 = ";D;H;L;P;T;X;\\;`;d;h;l;P<T<X<\\<`<" fullword ascii /* score: '1.00'*/
      $s46 = "?6?T?Z?" fullword ascii /* score: '1.00'*/
      $s47 = "xg;50bF" fullword ascii /* score: '1.00'*/
      $s48 = "u!h4bF" fullword ascii /* score: '1.00'*/
      $s49 = "0!03080B0Q0c0m0" fullword ascii /* score: '1.00'*/
      $s50 = ">0>K>c>" fullword ascii /* score: '1.00'*/
      $s51 = "xE;50bF" fullword ascii /* score: '1.00'*/
      $s52 = "5,505H5X5H<h<t<" fullword ascii /* score: '1.00'*/
      $s53 = "0 0(00080@0P0\\0|0" fullword ascii /* score: '1.00'*/
      $s54 = "VVVVhh" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s55 = "1 1$1(1,1014181<1@1D1H1L1P1d1h1l1p1t1x1|1" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s56 = "5$5<5@5X5h5l5p5x5" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65_12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d_8 {
   meta:
      description = "Amadey_MALW - from files b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65, 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1, 7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d, 488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77, 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c, 919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226, 8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197, ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65"
      hash2 = "12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
      hash3 = "7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d"
      hash4 = "488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
      hash5 = "5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
      hash6 = "919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
      hash7 = "8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197"
      hash8 = "ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
   strings:
      $s1 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s2 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s3 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s4 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s5 = " delete[]" fullword ascii /* score: '4.00'*/
      $s6 = " delete" fullword ascii /* score: '3.00'*/
      $s7 = " new[]" fullword ascii /* score: '1.00'*/
      $s8 = " Base Class Array'" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _0da5b00e8e941ac4be29830e6040cb5f_fff0ebef752c4e657f04529267347416_cc5e48eb9cf7308dedf57d5e468e836f_2964ea014ca6c3770dd7e283_9 {
   meta:
      description = "Amadey_MALW - from files 0da5b00e8e941ac4be29830e6040cb5f, fff0ebef752c4e657f04529267347416, cc5e48eb9cf7308dedf57d5e468e836f, 2964ea014ca6c3770dd7e28339348eb7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "6bd20157eb146f12887ccb49fa09ac5b0c817983edc43ca1b665f17ad3ebfb25"
      hash2 = "3d4fa915ede8b3a7d95155694abfe13c3ad26a65545fe1635797ff200ccdcb40"
      hash3 = "8babde64a6d3b85c2c4315205ae58884ee01f6364477a777f09d5b9c3ceef2a6"
      hash4 = "a1b0074cbd56956cc94e6161361f8f7407075f2903d14d082c1006f411bec90a"
   strings:
      $s1 = "Xagurorim zedojokit hikomulaHFal digan covorujiyexabih zetod bahohibinabok xupefamebubu ficexunidayid/Loye warojeguzuco pifayudo" wide /* score: '12.00'*/
      $s2 = "0Nukipixujabed jova mucater deyon denu jeyacidebo=Rosehozixenemac zikudizufu juxivodasede sogipamoco sijeneluhaBPipubey mofijodi" wide /* score: '10.00'*/
      $s3 = "@GetVice@0" fullword ascii /* score: '9.00'*/
      $s4 = ";Vewezacuj lorumozila yabo yugigot bocetisezibatin var gemig[Wulitocedala puyinimipotama nozi jeyavo kafigapur nilela dobe jecoh" wide /* score: '9.00'*/
      $s5 = "bvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s6 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s7 = "vvvvvvvvvvvvvvvvvvg" fullword ascii /* score: '8.00'*/
      $s8 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvs" fullword ascii /* score: '8.00'*/
      $s9 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s10 = "vvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s11 = "vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s12 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s13 = "ProductVersions" fullword wide /* score: '7.00'*/
      $s14 = "Beduyofimux xogozehuyawJNenayebinikove vuhanuzi gariluru jimagig rocesesun jim tedaj mupituhi vuvu+Gejipo puzikaha zuga mesohoyo" wide /* score: '7.00'*/
      $s15 = "Budefup" fullword wide /* score: '6.00'*/
      $s16 = "lvvvvvvvvvvvvvvvvvvvvv;" fullword ascii /* score: '4.00'*/
      $s17 = "vvvvvvvvvvvvvvvvvvvvvvvvvB" fullword ascii /* score: '4.00'*/
      $s18 = "$ hvvvvvvvvvvvvvvvvvvv2" fullword ascii /* score: '4.00'*/
      $s19 = "uSFvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s20 = "_Fvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s21 = "IHvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s22 = "R0U1vvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s23 = "vvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s24 = "L<W]vvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s25 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvv-vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s26 = "~8evvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s27 = "Qr!/{Mvvvvvvvvvvvvvvvvvvvvvvvvvj" fullword ascii /* score: '4.00'*/
      $s28 = "%vvvvvvvvvvvvvvvvvvA" fullword ascii /* score: '4.00'*/
      $s29 = "StringFileInform" fullword wide /* score: '4.00'*/
      $s30 = "Copyrighz (C) 2020, wodkagudy" fullword wide /* score: '4.00'*/
      $s31 = "Wobetesido suvesebuxomelot" fullword wide /* score: '4.00'*/
      $s32 = "Moba futumibe(Tanudipa wupavabifinax xemamaweladen marUPofunoc temamojavopu kajenulecola harilupulaz xuyiliso xucutuhabebe yujoy" wide /* score: '4.00'*/
      $s33 = "Hilegehihedo mekanisozu2Likarivasiga wejehumubere huhugoma vijutezumav fav" fullword wide /* score: '4.00'*/
      $s34 = "Ceh kijakadiniradow fafodarix2Zuvemabo dodap cuhuro bahudorebihoke gahodayikukew" fullword wide /* score: '4.00'*/
      $s35 = "D8`xhn" fullword ascii /* score: '1.00'*/
      $s36 = "/D@yk95" fullword ascii /* score: '1.00'*/
      $s37 = "HGd1*1xL" fullword ascii /* score: '1.00'*/
      $s38 = "%s %f %c" fullword ascii /* score: '1.00'*/
      $s39 = "!Sbs;-0" fullword ascii /* score: '1.00'*/
      $s40 = "QLso>8" fullword ascii /* score: '1.00'*/
      $s41 = "-IQhE&&" fullword ascii /* score: '1.00'*/
      $s42 = "`Ovvvvvvvv,vvvvvvvvvvvvvvvvvv" fullword ascii /* score: '0.00'*/
      $s43 = "Ciguxiwononici mezewi zitoro?Remapamuluyulad cajufa kuyarixin livozugenuc yisihu wecejegewuh" fullword wide /* score: '0.00'*/
      $s44 = "Gerifihebasazi gunihewinujHerudo nezetamar buvagogaxuca siroropuvuka visopuhibezem fagunilugidabo hekisiyofi hivijiko duyekuromu" wide /* score: '0.00'*/
      $s45 = "Pewuhomumiru gobakehoheg&Silekabecop gicov mupeyo yisapukezocazmWedidujo yow puxilin zewufo lazutahipof gixutezope yanazubowesoc" wide /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0da5b00e8e941ac4be29830e6040cb5f_fff0ebef752c4e657f04529267347416_10 {
   meta:
      description = "Amadey_MALW - from files 0da5b00e8e941ac4be29830e6040cb5f, fff0ebef752c4e657f04529267347416"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "6bd20157eb146f12887ccb49fa09ac5b0c817983edc43ca1b665f17ad3ebfb25"
      hash2 = "3d4fa915ede8b3a7d95155694abfe13c3ad26a65545fe1635797ff200ccdcb40"
   strings:
      $s1 = "FFFFFFFFF4" ascii /* reversed goodware string '4FFFFFFFFF' */ /* score: '15.00'*/
      $s2 = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s3 = "nvvvvvvvvvvvvvnnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s4 = "vvvvvvvvvvn" fullword ascii /* score: '8.00'*/
      $s5 = "nvvvvvvvvvvvvvnnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" ascii /* score: '8.00'*/
      $s6 = "nvvvvvvvvvvn" fullword ascii /* score: '8.00'*/
      $s7 = "rqmnmso" fullword ascii /* score: '8.00'*/
      $s8 = "rinakimuhuzafoluj" fullword ascii /* score: '8.00'*/
      $s9 = "jivuzibibewuyadoruxecidowuguxodolenatumefefirarenolepiwurupuxoyijekoruhe" fullword wide /* score: '8.00'*/
      $s10 = "Daporesen cic.Nek hozuheritihos kenelatokupuj jurubenidajiza" fullword wide /* score: '7.00'*/
      $s11 = "FFFFFFFFFFFFFFFFFFF" ascii /* score: '6.50'*/
      $s12 = ".www.&" fullword ascii /* score: '4.00'*/
      $s13 = "eeee{{{" fullword ascii /* score: '4.00'*/
      $s14 = "Boruka hipeturuhog" fullword ascii /* score: '4.00'*/
      $s15 = "vvvvvvvvvvvn{" fullword ascii /* score: '4.00'*/
      $s16 = "8Hofozopuyawa xodolivabic faleki huvidobeyawo kigepirolef" fullword wide /* score: '4.00'*/
      $s17 = "nvvvvvvvvvv" fullword ascii /* score: '2.00'*/
      $s18 = "vvnnnnnnnnnnnnnnnnnvvvvvvvvvvvvvn" fullword ascii /* score: '2.00'*/
      $s19 = "nvvvvvvvvvvv" fullword ascii /* score: '2.00'*/
      $s20 = "e----------------e" fullword ascii /* score: '1.00'*/
      $s21 = "e--------------" fullword ascii /* score: '1.00'*/
      $s22 = "G%%%%%%%GGGG" fullword ascii /* score: '1.00'*/
      $s23 = "E,,,,," fullword ascii /* score: '1.00'*/
      $s24 = "g''''g" fullword ascii /* score: '1.00'*/
      $s25 = "xsy]vvv" fullword ascii /* score: '1.00'*/
      $s26 = "wpw]trq" fullword ascii /* score: '1.00'*/
      $s27 = "x~xquyu" fullword ascii /* score: '1.00'*/
      $s28 = "'Mivamivusotaj kukidi sasur tuhozi hemor\\Hamofehexebawal fogibubivaru yuropec sareresar yivayazecahulu fimurihulakure cimeyunaw" wide /* score: '0.00'*/
      $s29 = "Rerewarih`Zenodetuwopaha zecupikizeyoley yanevobi pogicavomefosaw zowivapijerav gozirenuwadif vewiziwalefi4Bozazadas huf pimiges" wide /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65_5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08_11 {
   meta:
      description = "Amadey_MALW - from files b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65, 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65"
      hash2 = "5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
   strings:
      $s1 = "676A6K6b6l6" fullword ascii /* score: '1.00'*/
      $s2 = ";7;A;K;b;l;" fullword ascii /* score: '1.00'*/
      $s3 = "<!<+<B<L<w<" fullword ascii /* score: '1.00'*/
      $s4 = "4\"4,4W4a4k4" fullword ascii /* score: '1.00'*/
      $s5 = "7!7+7B7L7w7" fullword ascii /* score: '1.00'*/
      $s6 = "171A1K1b1l1" fullword ascii /* score: '1.00'*/
      $s7 = ";\";,;W;a;k;" fullword ascii /* score: '1.00'*/
      $s8 = ":\":,:W:a:k:" fullword ascii /* score: '1.00'*/
      $s9 = "9\"9,9W9a9k9" fullword ascii /* score: '1.00'*/
      $s10 = "5!5+5B5L5w5" fullword ascii /* score: '1.00'*/
      $s11 = "=\"=,=W=a=k=" fullword ascii /* score: '1.00'*/
      $s12 = ";!;+;B;L;w;" fullword ascii /* score: '1.00'*/
      $s13 = "8\"8,8W8a8k8" fullword ascii /* score: '1.00'*/
      $s14 = "474A4K4b4l4" fullword ascii /* score: '1.00'*/
      $s15 = "?!?+?B?L?w?" fullword ascii /* score: '1.00'*/
      $s16 = "6\"6,6W6a6k6" fullword ascii /* score: '1.00'*/
      $s17 = ":7:A:K:b:l:" fullword ascii /* score: '1.00'*/
      $s18 = "2!2+2B2L2w2" fullword ascii /* score: '1.00'*/
      $s19 = ":!:+:B:L:w:" fullword ascii /* score: '1.00'*/
      $s20 = ">7>A>K>b>l>" fullword ascii /* score: '1.00'*/
      $s21 = "575A5K5b5l5" fullword ascii /* score: '1.00'*/
      $s22 = "1\"1,1W1a1k1" fullword ascii /* score: '1.00'*/
      $s23 = "9!9+9B9L9w9" fullword ascii /* score: '1.00'*/
      $s24 = "272A2K2b2l2" fullword ascii /* score: '1.00'*/
      $s25 = "777A7K7b7l7" fullword ascii /* score: '1.00'*/
      $s26 = "3!3+3B3L3w3" fullword ascii /* score: '1.00'*/
      $s27 = ">!>+>B>L>w>" fullword ascii /* score: '1.00'*/
      $s28 = "0!0+0B0L0w0" fullword ascii /* score: '1.00'*/
      $s29 = "<7<A<K<b<l<" fullword ascii /* score: '1.00'*/
      $s30 = "?\"?,?W?a?k?" fullword ascii /* score: '1.00'*/
      $s31 = "5\"5,5W5a5k5" fullword ascii /* score: '1.00'*/
      $s32 = "6!6+6B6L6w6" fullword ascii /* score: '1.00'*/
      $s33 = "=7=A=K=b=l=" fullword ascii /* score: '1.00'*/
      $s34 = "2\"2,2W2a2k2" fullword ascii /* score: '1.00'*/
      $s35 = ">\">,>W>a>k>" fullword ascii /* score: '1.00'*/
      $s36 = "0\"0,0W0a0k0" fullword ascii /* score: '1.00'*/
      $s37 = "4!4+4B4L4w4" fullword ascii /* score: '1.00'*/
      $s38 = "8!8+8B8L8w8" fullword ascii /* score: '1.00'*/
      $s39 = "?7?A?K?b?l?" fullword ascii /* score: '1.00'*/
      $s40 = "3\"3,3W3a3k3" fullword ascii /* score: '1.00'*/
      $s41 = "=!=+=B=L=w=" fullword ascii /* score: '1.00'*/
      $s42 = "7\"7,7W7a7k7" fullword ascii /* score: '1.00'*/
      $s43 = "070A0K0b0l0" fullword ascii /* score: '1.00'*/
      $s44 = "979A9K9b9l9" fullword ascii /* score: '1.00'*/
      $s45 = "878A8K8b8l8" fullword ascii /* score: '1.00'*/
      $s46 = "1!1+1B1L1w1" fullword ascii /* score: '1.00'*/
      $s47 = "373A3K3b3l3" fullword ascii /* score: '1.00'*/
      $s48 = "<\"<,<W<a<k<" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1_488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791_12 {
   meta:
      description = "Amadey_MALW - from files 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1, 488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77, 919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226, ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
      hash2 = "488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
      hash3 = "919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
      hash4 = "ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
   strings:
      $s1 = "9':1:;:R:\\:" fullword ascii /* score: '7.00'*/
      $s2 = "323<3g3q3{3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "2G2Q2[2r2|2" fullword ascii /* score: '1.00'*/
      $s4 = "8G8Q8[8r8|8" fullword ascii /* score: '1.00'*/
      $s5 = "6G6Q6[6r6|6" fullword ascii /* score: '1.00'*/
      $s6 = ":2:<:g:q:{:" fullword ascii /* score: '1.00'*/
      $s7 = "7'818;8R8\\8" fullword ascii /* score: '1.00'*/
      $s8 = "=2=<=g=q={=" fullword ascii /* score: '1.00'*/
      $s9 = ">2><>g>q>{>" fullword ascii /* score: '1.00'*/
      $s10 = "6'717;7R7\\7" fullword ascii /* score: '1.00'*/
      $s11 = "9G9Q9[9r9|9" fullword ascii /* score: '1.00'*/
      $s12 = "<G<Q<[<r<|<" fullword ascii /* score: '1.00'*/
      $s13 = ";'<1<;<R<\\<" fullword ascii /* score: '1.00'*/
      $s14 = "222<2g2q2{2" fullword ascii /* score: '1.00'*/
      $s15 = "1G1Q1[1r1|1" fullword ascii /* score: '1.00'*/
      $s16 = "<2<<<g<q<{<" fullword ascii /* score: '1.00'*/
      $s17 = "='>1>;>R>\\>" fullword ascii /* score: '1.00'*/
      $s18 = "424<4g4q4{4" fullword ascii /* score: '1.00'*/
      $s19 = "4G4Q4[4r4|4" fullword ascii /* score: '1.00'*/
      $s20 = "828<8g8q8{8" fullword ascii /* score: '1.00'*/
      $s21 = "7G7Q7[7r7|7" fullword ascii /* score: '1.00'*/
      $s22 = "5'616;6R6\\6" fullword ascii /* score: '1.00'*/
      $s23 = "020<0g0q0{0" fullword ascii /* score: '1.00'*/
      $s24 = ">G>Q>[>r>|>" fullword ascii /* score: '1.00'*/
      $s25 = "?G?Q?[?r?|?" fullword ascii /* score: '1.00'*/
      $s26 = "0'111;1R1\\1" fullword ascii /* score: '1.00'*/
      $s27 = "3G3Q3[3r3|3" fullword ascii /* score: '1.00'*/
      $s28 = "'010;0R0\\0" fullword ascii /* score: '1.00'*/
      $s29 = ">'?1?;?R?\\?" fullword ascii /* score: '1.00'*/
      $s30 = "?2?<?g?q?{?" fullword ascii /* score: '1.00'*/
      $s31 = "727<7g7q7{7" fullword ascii /* score: '1.00'*/
      $s32 = "121<1g1q1{1" fullword ascii /* score: '1.00'*/
      $s33 = "525<5g5q5{5" fullword ascii /* score: '1.00'*/
      $s34 = "1'212;2R2\\2" fullword ascii /* score: '1.00'*/
      $s35 = "8'919;9R9\\9" fullword ascii /* score: '1.00'*/
      $s36 = "2'313;3R3\\3" fullword ascii /* score: '1.00'*/
      $s37 = ":';1;;;R;\\;" fullword ascii /* score: '1.00'*/
      $s38 = "=G=Q=[=r=|=" fullword ascii /* score: '1.00'*/
      $s39 = ";2;<;g;q;{;" fullword ascii /* score: '1.00'*/
      $s40 = ":G:Q:[:r:|:" fullword ascii /* score: '1.00'*/
      $s41 = ";G;Q;[;r;|;" fullword ascii /* score: '1.00'*/
      $s42 = "5G5Q5[5r5|5" fullword ascii /* score: '1.00'*/
      $s43 = "929<9g9q9{9" fullword ascii /* score: '1.00'*/
      $s44 = "626<6g6q6{6" fullword ascii /* score: '1.00'*/
      $s45 = "<'=1=;=R=\\=" fullword ascii /* score: '1.00'*/
      $s46 = "3'414;4R4\\4" fullword ascii /* score: '1.00'*/
      $s47 = "4'515;5R5\\5" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0da5b00e8e941ac4be29830e6040cb5f_fff0ebef752c4e657f04529267347416_2964ea014ca6c3770dd7e28339348eb7_13 {
   meta:
      description = "Amadey_MALW - from files 0da5b00e8e941ac4be29830e6040cb5f, fff0ebef752c4e657f04529267347416, 2964ea014ca6c3770dd7e28339348eb7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "6bd20157eb146f12887ccb49fa09ac5b0c817983edc43ca1b665f17ad3ebfb25"
      hash2 = "3d4fa915ede8b3a7d95155694abfe13c3ad26a65545fe1635797ff200ccdcb40"
      hash3 = "a1b0074cbd56956cc94e6161361f8f7407075f2903d14d082c1006f411bec90a"
   strings:
      $s1 = "voygcuadage.exe" fullword wide /* score: '22.00'*/
      $s2 = "vvvvvv," fullword ascii /* reversed goodware string ',vvvvvv' */ /* score: '14.00'*/
      $s3 = "runexobozez" fullword ascii /* score: '11.00'*/
      $s4 = "vvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s5 = "kevvvvvvvvvvvv" fullword ascii /* score: '8.00'*/
      $s6 = "Kenegodiza sikimec covituwutaPPuloperehodop xew pazefom lurefazuyod gesoru gadumolop facelimame lihobiboc tibe#Lovul vefewaripuy" wide /* score: '5.00'*/
      $s7 = "Muxewejakoni/Himekapusacec xumayojub baj curi gofirakokiboluYGafayecixuvux now gulamakavidicu ziyuyedin zunixoregomofa zit laxek" wide /* score: '5.00'*/
      $s8 = "(vvvvvvvv" fullword ascii /* score: '4.00'*/
      $s9 = "%vvvvvvvvvvvv" fullword ascii /* score: '4.00'*/
      $s10 = "vvvvvvvvvvv," fullword ascii /* score: '4.00'*/
      $s11 = "Pucewuhon repisotujoduxoyNJiyipixohorag deceh zoxebej nek fogi nayikux dufa sebumili mugizefilaret wegipJNugakidegamew navisoxud" wide /* score: '4.00'*/
      $s12 = "Hoxazawiwod fupucu" fullword wide /* score: '4.00'*/
      $s13 = "Bajuhozaximepo nitisi" fullword wide /* score: '4.00'*/
      $s14 = "Bimecefef hefayuguxogesIVeguwakan rojiyutirabila tuxij dexa jehoposabem tijoxexuj vixaxasiju gowe8Rigoniropigox kujakiyasu huba " wide /* score: '4.00'*/
      $s15 = "nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" fullword ascii /* score: '2.00'*/
      $s16 = "ut~Qx|" fullword ascii /* score: '1.00'*/
      $s17 = "vvvvvvvv-vv" fullword ascii /* score: '0.00'*/
      $s18 = "EvvvvvvvOj" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf_d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd306_14 {
   meta:
      description = "Amadey_MALW - from files 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf, d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b, 707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6, ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10, 4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515, 2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806, 6738c904ba78a2268a8950152a6c7448"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
      hash2 = "d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b"
      hash3 = "707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6"
      hash4 = "ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10"
      hash5 = "4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
      hash6 = "2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
      hash7 = "42054b960727fbd72bde57e8903881e4239e9500f1160ca298e10a1b438698a8"
   strings:
      $s1 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s2 = "          version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s3 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s4 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s5 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s6 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s7 = "a2440225f93a" ascii /* score: '1.00'*/
      $s8 = "6595b64144ccf1df" ascii /* score: '1.00'*/
      $s9 = "48fd50a15a9a" ascii /* score: '1.00'*/
      $s10 = "d69d4a4a6e38" ascii /* score: '1.00'*/
      $s11 = "83d0f6d0da78" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _142cbad8b9d400380c78935e60db104ec080812b1a298f9753a41b2811c856be_1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7c_15 {
   meta:
      description = "Amadey_MALW - from files 142cbad8b9d400380c78935e60db104ec080812b1a298f9753a41b2811c856be, 1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "142cbad8b9d400380c78935e60db104ec080812b1a298f9753a41b2811c856be"
      hash2 = "1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061"
   strings:
      $s1 = "word/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "word/webSettings.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "word/fontTable.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "word/document.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "word/settings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "word/webSettings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "word/styles.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s11 = "word/fontTable.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s12 = "word/settings.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s13 = "word/document.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515_2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc_16 {
   meta:
      description = "Amadey_MALW - from files 4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515, 2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
      hash2 = "2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
   strings:
      $s1 = ".J/};EM" fullword ascii /* score: '1.00'*/
      $s2 = "hW:U9b" fullword ascii /* score: '1.00'*/
      $s3 = "%ZABEf`" fullword ascii /* score: '1.00'*/
      $s4 = "'a%U{y9p9" fullword ascii /* score: '1.00'*/
      $s5 = "'N{zNMI" fullword ascii /* score: '1.00'*/
      $s6 = "w@4u:L" fullword ascii /* score: '1.00'*/
      $s7 = "O\\g<Wf" fullword ascii /* score: '1.00'*/
      $s8 = "{.L)*\\)" fullword ascii /* score: '1.00'*/
      $s9 = "Z:nb5<" fullword ascii /* score: '1.00'*/
      $s10 = "@_le1A" fullword ascii /* score: '1.00'*/
      $s11 = "`^Rv|Q[87/g" fullword ascii /* score: '1.00'*/
      $s12 = "(#O%zs" fullword ascii /* score: '1.00'*/
      $s13 = "4A/skX" fullword ascii /* score: '1.00'*/
      $s14 = "HnACZ:" fullword ascii /* score: '1.00'*/
      $s15 = "uXR2O\\" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "1efe015ade03f54dd6d9b2ccea28b970" and ( 8 of them )
      ) or ( all of them )
}

rule _12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1_488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791_17 {
   meta:
      description = "Amadey_MALW - from files 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1, 488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77, 919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1"
      hash2 = "488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
      hash3 = "919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226"
   strings:
      $s1 = "07c6bc37dc50874878dcb010336ed906" ascii /* score: '3.00'*/
      $s2 = "3 4(40484@4H4P4X4`4h4p4x4" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "h1p1x1|1" fullword ascii /* score: '1.00'*/
      $s4 = "2 2$2(2,2024282<2@2D2H2L2P2T2X2\\2`2d2(7,7074787<7@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7" fullword ascii /* score: '1.00'*/
      $s5 = "1 1$1(1,1014181<1@1T1X1\\1`1d1h1l1p1t1x1|1" fullword ascii /* score: '1.00'*/
      $s6 = "7 7$7(7,70747@7D7H7`7d7h7" fullword ascii /* score: '1.00'*/
      $s7 = "/SPPWh" fullword ascii /* score: '1.00'*/
      $s8 = "= =$=(=,=0=4=8=L=P=T=X=\\=`=d=h=l=p=t=x=|=" fullword ascii /* score: '1.00'*/
      $s9 = ";4;8;<;@;D;H;L;P;T;X;\\;@<D<H<L<P<" fullword ascii /* score: '1.00'*/
      $s10 = "7$7,747<7D7L7T7" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s11 = "7$7(7,7074787<7t:|:" fullword ascii /* score: '1.00'*/
      $s12 = "3 3$3(3,3034383<3@3D3H3L3P3T3d3h3l3p3t3x3|3" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77_5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08_18 {
   meta:
      description = "Amadey_MALW - from files 488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77, 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c, ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77"
      hash2 = "5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c"
      hash3 = "ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839"
   strings:
      $s1 = "CMPQPQ" fullword ascii /* score: '3.50'*/
      $s2 = "00000423" ascii /* score: '1.00'*/
      $s3 = "00000422" ascii /* score: '1.00'*/
      $s4 = "CM8QPQ" fullword ascii /* score: '1.00'*/
      $s5 = "0000043f" ascii /* score: '1.00'*/
      $s6 = "00000419" ascii /* score: '1.00'*/
      $s7 = "pEjjjj" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _cc5e48eb9cf7308dedf57d5e468e836f_2964ea014ca6c3770dd7e28339348eb7_19 {
   meta:
      description = "Amadey_MALW - from files cc5e48eb9cf7308dedf57d5e468e836f, 2964ea014ca6c3770dd7e28339348eb7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "8babde64a6d3b85c2c4315205ae58884ee01f6364477a777f09d5b9c3ceef2a6"
      hash2 = "a1b0074cbd56956cc94e6161361f8f7407075f2903d14d082c1006f411bec90a"
   strings:
      $s1 = "Daporesen cic.Nek hozuheritihos kenelatokupuj jurubenidajiza+Mevu zigu rubacoluye jipebe ciheyevasetotot" fullword wide /* score: '12.00'*/
      $s2 = "@GetFirstVice@0" fullword ascii /* score: '9.00'*/
      $s3 = "budesorozefabijicu" fullword wide /* score: '8.00'*/
      $s4 = "Megotuzoteneri" fullword ascii /* score: '6.00'*/
      $s5 = "XGuci sevuborigili poxocakef gawituvico dadukolan soviwavitafec tuhonol liyo zilameluxaruZVujun lavicomepit xavedoboxum tinuvovu" wide /* score: '6.00'*/
      $s6 = "081504b6" wide /* score: '1.00'*/
      $s7 = "Rerewarih`Zenodetuwopaha zecupikizeyoley yanevobi pogicavomefosaw zowivapijerav gozirenuwadif vewiziwalefi" fullword wide /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( all of them )
      ) or ( all of them )
}

rule _0da5b00e8e941ac4be29830e6040cb5f_cc5e48eb9cf7308dedf57d5e468e836f_2964ea014ca6c3770dd7e28339348eb7_20 {
   meta:
      description = "Amadey_MALW - from files 0da5b00e8e941ac4be29830e6040cb5f, cc5e48eb9cf7308dedf57d5e468e836f, 2964ea014ca6c3770dd7e28339348eb7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "6bd20157eb146f12887ccb49fa09ac5b0c817983edc43ca1b665f17ad3ebfb25"
      hash2 = "8babde64a6d3b85c2c4315205ae58884ee01f6364477a777f09d5b9c3ceef2a6"
      hash3 = "a1b0074cbd56956cc94e6161361f8f7407075f2903d14d082c1006f411bec90a"
   strings:
      $s1 = "Basiw cujadehocenis" fullword ascii /* score: '4.00'*/
      $s2 = "Yamohinifo bowi nenukodabebive goyigavu sofusixuyogo" fullword wide /* score: '4.00'*/
      $s3 = "Yav fug" fullword ascii /* score: '1.00'*/
      $s4 = "1.16.46" fullword wide /* score: '1.00'*/
      $s5 = "Cafefawotiweh rexic sulorabasekibak" fullword wide /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( all of them )
      ) or ( all of them )
}

rule _4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf_2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc_21 {
   meta:
      description = "Amadey_MALW - from files 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf, 2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
      hash2 = "2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806"
   strings:
      $s1 = " Qe.hzs{" fullword ascii /* score: '4.00'*/
      $s2 = "RCKSZE" fullword ascii /* score: '3.50'*/
      $s3 = "GmB\"s]" fullword ascii /* score: '1.00'*/
      $s4 = "3\\_cKpC" fullword ascii /* score: '1.00'*/
      $s5 = "jPpI;[" fullword ascii /* score: '1.00'*/
      $s6 = "lAaH~v" fullword ascii /* score: '1.00'*/
      $s7 = "h$ZwE5" fullword ascii /* score: '1.00'*/
      $s8 = "aa{mkm" fullword ascii /* score: '1.00'*/
      $s9 = "_w~wv6" fullword ascii /* score: '1.00'*/
      $s10 = "p|VLO`" fullword ascii /* score: '1.00'*/
      $s11 = "TT|Hff" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "1efe015ade03f54dd6d9b2ccea28b970" and ( 8 of them )
      ) or ( all of them )
}

rule _4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf_4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117_22 {
   meta:
      description = "Amadey_MALW - from files 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf, 4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
      hash2 = "4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
   strings:
      $s1 = "Fhrfa\"" fullword ascii /* score: '4.00'*/
      $s2 = "TTSi55" fullword ascii /* score: '2.00'*/
      $s3 = "\\!?8_=;" fullword ascii /* score: '2.00'*/
      $s4 = "{sZ6rdZ" fullword ascii /* score: '1.00'*/
      $s5 = "%%\\.=r" fullword ascii /* score: '1.00'*/
      $s6 = "}z;AYWSi" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "1efe015ade03f54dd6d9b2ccea28b970" and ( all of them )
      ) or ( all of them )
}

rule _4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf_d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd306_23 {
   meta:
      description = "Amadey_MALW - from files 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf, d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b, 4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-03-27"
      hash1 = "4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf"
      hash2 = "d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b"
      hash3 = "4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515"
   strings:
      $s1 = "jYVp!G:" fullword ascii /* score: '4.00'*/
      $s2 = "jYW)4XiC" fullword ascii /* score: '1.00'*/
      $s3 = "X .UG " fullword ascii /* score: '1.00'*/
      $s4 = "AU!cGRn" fullword ascii /* score: '1.00'*/
      $s5 = "O]$2so" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "1efe015ade03f54dd6d9b2ccea28b970" and ( all of them )
      ) or ( all of them )
}

