#!/usr/bin/env python3
"""Offline VPN config decoder: HC, DarkTunnel and SSH Custom.

HC implementation bundled from the user's HttpCustomAllversion.py.
DarkTunnel algorithm: https://github.com/YumeeKunn/darktunnel-decrypt
SSC algorithm adapted from kralonur/multi-vpn-decryptor-rs (MIT):
https://github.com/kralonur/multi-vpn-decryptor-rs
Copyright (c) 2026 kralonur
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import argparse
import base64
import getpass
import hmac
import json
from pathlib import Path
import struct
import sys
import types
import zlib

HC_SOURCE = 'c-rlKU6b2LlGuCy3Jh*<n;5Yv0t88rJ3YH>cK1j-T1hKuW_PdELxTX=<cLjj2~z4FNf+mEI2^XazHpo!4xhueUL1b%qaz%S@t@Hj@LzCd)(5J90?F3L?Z-(m!zO{MtgNi8tjw&etjXnKzFb-3Fda`P!@UXrc^O9H`}gU5CcdYu<vLo4U-MLa8-{7p^5w6|EKH-xMEqVR;@f4o8t;vk^Gj=Wy_n1{EdIPVyRKTtlW0}7?yiz$IGiR`>)s@V-wzh6$$S=0tJahCVw&u&me<`q3;q$9{_=XUn%DZ1#W-0CX#H^r|9SPQ)jN4yDErN7GOaxf<5+2bJzIn^mFz$I-NPpj2EA{4cklI%?wweN)|2Hr*-NgXWU;dDQu&kRa=z@Al|K!qX|ngQ*Z;cr75*ODSJyw(k}$nqEa$cHYPE>g>1uvy?>+eD$;qQZuXjwP?(~1_zA_hm<%+_OPfl3radeQ(o+s1!A~{HtaC-3EwKlhN=j-Fs!Q<Y&C+7NTI9&k{t@Pddrw`1fC$rI9DgE`y?*`vCu;}$FNoz>&adK5564^n}u6yyQ6(&Jc4?0oDZwJF5ioIdn7&YphmOE@T+kV&#>a9jx_xxcTHS43+u-)z?UTb9UIeYipgFC<K^|7InRyxD5JsLHJ;i%DwhwU(ogL*p*S^#<2j>2Yhn2fwp-4Bv5Zn~pJ=#G+l1T}(AJZuab*h;@XczmblHCuy+k4{eS{<f^CW*qy_N;~nx`Y?gcHJee?@|w*?5=Wyb7}eYDQPK|JWixEYfLPFSBX}RgksAQj2uvf0!r{=b54};~hRv{1AG&VXX-C6oR39aAyV(rGAo7Myztc=Q!>As)ow^6GLqCc;9%39#!!)(-^pBGW*_$}C@@+U>C-l`}T)KcldvP+d22p(wPcD*lRf)q@*k#>wtb;GvH&%R^tk%n!5DK*vCR4LjDG=wDg)p2N2k5XC#?Ru>fLED3yW~w&E#xox1KCIZm?pD})wl}}S3vNFmq%wZ;zg`4thzN{ieFz^KvC=SJe~rfK|1*%VGyWO;UrD0j5HN{GJ76QC$WXBZq3)L#d^g-+YTe!@);n6!mu_=UR1CLfcmq`YOYCz1XzuOV!RVBm*I6qz)PM_=IfNE6k~#DzMg@^gC{Qielea*6U3szpg7QHP9ND51&qWEP_1S!ZV`du4^gpl##=dewqTxNUrVl5$t<o2klA~I@hyQe=N8r!t9{mGIG=N#Sk9*nuksvePs3b=HDZ<0R~l^it8re1m9@V3f(km;Pp$gZDgWnKuPpxl%P*};!?O-pDc;!c*WnTnghtoUfpitFpix{*&Y+p|suc<p_}_^CjWc}i&u5%-sQOuW4z#Yw@3;8l;kk~PQX|G1yx;Q4cM@FHa$Am4JW?8nvIgSv28M+OhFJp<HsCoQw+F#T?m$~I4~%147|7f}jX*98U;tsB&n}XRTX(VvV`7P_1^R&xy~rq4Uev8x&8pRbFO6+Qy{grMasb@*x0P)`C!ribcbm?3Y?~Zza|d)=9Im$mzHLT@#t!KEj0(Px_0c$tP}QnDORl9npUr1c;<ic_7beZIf@6J#;+{+N3a>^_p>|Gi=a#rkcnfV0#=aoH32|VvDKJe%0%Tfj4VAv=S;hXsziWduu#>ArIEw+H1H{&PW@q%cRj3nS9qhw~G6YxjipsH1jiVh^?r{iIUjk;0DcIu#slx<e-(304liwQW`SNb|(rsj4{p@R#*Wp7eMs_fq&H<a^_<Hg;UlB6#x%+5)Y_z>yM|;y?PiB+VB%J<(4R=MXgsOn6Zi3Rt7{XH-La-_CK`ojugvxMZUU6I4$mbO<Qzz%73=mxSp-W>DniEB6wj4+00cau#F9%mJ0*basgxHB0P^-x^gh4q%b|6jCk&>L4ZZKP44wGfonvX_lvO+u)cm($0DycAx>!dxh+933NN0Isrdt79Sye#pqX8MfQsG{$T*E3WDv5hl^NtYvZ3tBvv1&Nqdi)khrt^`8CEThAjgfzkBkk$Q;qYmR$reN^_TFj@{Zlm6;TqbE6UL<l9U|AfjCYQ+|8>*6-sg~qZbl1uFkhhMl9Uu&33_gvP#Lg=+oCX|orKPj3+XB&JPbaI@G?8_FdI;QEXUy3z`FqMOns`eKu!Iy^2%~6yxt@lrIpSBRXP5JMJtbwj;-bO{Jpxi$P05QH_h~%GN$!v;mywK^2!Qd|1&)D!%d$E;6^%bC>dRaCp0ZYeW$mX|b=Ow<>3~7Bl#m?jFGUA+{aS|()I`Zp;S}%!q=4%<wbh(A=(bc^GUf|ox3z;A38s!<Hkzk^lH0Nlf&Nx91@@vo)NQ~UT7h=;g1oUSF^2`q4`RlXgT;E8FwzyolKd5haVDV1SF{5AW&rYkunI5utGzt_>3RqtQGjTA4hK#w%-D*{5;E(sFY5m`ke8K5hGaIM!~kj((K+iL2qsC_i^X)3&|`Di0|`}SeuL0sol)do-8t(vJXRO1$N^hXRW<~w0rGsD;fK1kDSePdvS)@xkS~G1w%P1KaNA2M5Y_b(mhL24NwO$nQ1nBWfQ}G&vpMr^!U}u22$zZQg{T0l8r7X`!tl33B{`7dFkG+3$!s-=LUdhPqYzB`*wz+rb!p8yS+xqI<d*V(GJ7}vUra*~CeYd+l<idlNQ}(=|3}8$oI`RrY~^s`l5lx3pLvtmZB(S+@5Ou>o1Jj;MLL~aPFCFiahY7IKl5I>y%GfiLGEU=jqKi|uO8g@?jE}h!o<2<rz>li;CjGux_}w_Qi6SL%c(1nwZ1rHPC$Wf@c}Fwb<f{bi&1c*>M7IRn6sO=FE<_JX2L9trnSWj^rneT1VMbu`U~9NKu_1jY`#n~JlM#Ja<ymiNMG|A$*bBkF@*Y4az*O;B&W}z_@ciS#5ojSve!bUnm0J4``Ane)|uLL{$emqfM$XiPk;c-**Hjn?8$1d3}0-cOs;t4od`iwBATZgC^27Nvl5bJZr>)J$&-E=PNxZ2lb46C{)#Y#;W{)88Fujy2~fLxtiO4lEK^t#4&BZNB0n+o{9+j{#@DrR_`_ugVrGe5nmkWZ<ggkWA-U7GBa@19l>)U7izH`6Fw$az+j+PQrX|BM4QEN3C+}`!<kaG13H_`H*3d{<QD|AUdaKoPGF-2;ZIN=~a%x3LqSXAfwq8x9nUx3%*#xxK1PzHZtuvrD57T)(Szp%DdChCs)$-SdcYKCHRd>_d{JYzzLbDH0c4{yTm+PzBBTz-s+v{|B8|vQP)bft?P3>m}PC6K&`vO(hjApgb1e8~(y9}4t6`Nt8cwa!+i+bpw5#LdF1Ie5bTDPaO=e5Z!g_RTSG+sA@9qxb->ynO8s2~)+2SQ;UAv7@4`7FFlHo?+(Q_h^pFzZME_};w=1LPD+LI*%#g)jvwPzek<CN>6a{j!}RZ0?~zjfpo94c6o*`<%~qr{WlEf&3s3+_0uKQZW|h%~VTYW{pqhvkUyc!kaIzV_qn>L(Rm<2H-{Ew*|0}dd?2DaKm!2stAd<OBK-0DqcxJ^8f)e&=`T%)GdXdcR3Y7!Lpd=Dxug6Xmx}I{9|!ep`pqSBLb9acsCjjUM0T(-Jq)bUTmuI<h!z@)TOKMHUmwI`bTFlv4lT(ylwf;cBR4Ko~;vA12~~SpnDirdu9_nTF+2jWEMf@L>ELqSS;r&atv6taYTLr7SHti^<)Vv{o)$UfGSsl52Dd%Qq@$lD(!ZNRn}I0>!l8@kK@ZK?89ue)r5T{9UO?0v<hDeXo`s@w{@tAtrnQ6397C)!XW0FDRvwKCARMxDpvI*wbJn%cR8)qIGkB%`AHWJ04z2AHpZL{B#1Hvo1p-btWbplIe?~znJ?pz^*&d*wqBr;pt~(Jzd=oSN0B;UbxcOrl`>CbwbZY81Ji^T%ED``FvW)-&V9y+4<I*L<U`QpCbNrFs_IM!36n53%(zLi8i{FFI$jy@M932fp0NV!uc`hf(g{!C7SDFZ3pDjjgJob;!3;ZhUtd9sZScl9B7l_HepLzb@fcvUNA!a_L;qal=AVohQ@!Epu18JyyOANe+g^@di4^4CQvmZmK9+YCEF9qvC>S)Ce?c(hsIj{U(B=&hBXh``W<A$nKx<2u=zOjeCe1Up?Ji?Yv)E;Q7bF)eTD5YK%Gv`AMi#*-;c_{F#xr}lf}RPsSE=qsifHmPdUVb=IFe)r_@#*mdyLl0WkPQ542mhJOx@>&c`K^HdjzQ~rNd<sKFb^-@V*wtafR2>oC~DT@aNW-C;@1nSci8#Nv5%Aa<9}eAa)g5IaCAYaZ<6@tI<KAxHLHbeKVWj`(rAVW5Z%6_y$@yomN0Ot^g-39rC_k@lX<cg47@;+yrSlzX0hz72(wixB?iBP@<ab;HE~hQRVeG+b)tB=Uw6DFJT@$kZ_i+(EONPbKc?mPYUnvF)wDi8YDzOd1B#A+8-F&fsu-mr$k4flbd;2XE<aOUKQ0{BcEu7kdZ~??8c64F+<dUByf21XI&3N$K(Nq>;)`e=X>QwB8zZ2q*Eoe={$_nOp52ZRj<jpZ<0=C=_&+)#A1M}Rt&>run5iS1`V7-0<Z#zr>$Q;esJHK55EU<&(<5}!irkUPoRnpziOCKRn}L8uRL`M>XFVyKq8^)8V8Xr_=nnfl&Ek@DHxmsH2|e-yH`EbQQY^{aM*qS*T{c2*a!b$Y*fNR<lLnPwF_7p>=0B=kTmw4e*g3<+rVIdV7@Ric;>_)ww`6mv~XV}v32LklZRHH4hNyU7)>tLY?CJ2_hbt_Q-HG8nFJ-}69iQzKgE}BPG;)C{XlwAFr)Bi1`3y`z3W-l1p&yq41u++mm1*xaNqfCX;gjFXq;SzEOe}*V>1-2BE}H6@c2+ECu(-IYlMz25oIms?O5FG;3yqhZdc(W9+4vTY_OE>^x!|Q{t)G~T`UU96qdW+dvf>NlLOS54%mSmR+c=ryfIjKDjr3Yx1EiRrfzvdV^;u9lXn|Dj?M7!CHs~Q8vKl&;a=LyjH4sFn@2J8OWLve7BFP5UduIigbGyEdJ)bL1>9_*CTf#aa+y{XDumH$O}dH39#mc56Jq6nff-DF%5I*W(!em&g&MP7(jTA+Sahs0`2I85N$VwR7l~$Aagn0&dYa@rVkep9Da-J^tcpFOV8WS4pKbaK>}^3%dpmb&KiP-Qh-UTf?9bf&DtvnM+1@AT>HaL(w{yM*5dcjrLm~;}IRb$d>;|fwMD1{!Qn({Qh1+<Lxs73IoX@8@K{K{7K#2pL&R1yx;v7nxoo6Km6r_v`IePQ4ij!N&=wX#2-yIfKSuYGS8(>ciDy?@#oYiw?^a$4lob4|r@hwq2Cs9n`H^EV=?~XveZB^*#B|&T8D;Q@LMTpRPfubV65-FmDi|Tx#p;m|qphBTYD+F?=P$Je#B-aB$LMSS}DkVlq2%SjM0-zD&5~V1QFBzaZQ7Ass+RZ2i1+yR3;x5R*)QM*{aiD?aiTTjlF@X}>Zv}YMcY`PP<_hpGZv+o{a*$0l90&PBtRtlQ@UcL(buzoytoOh#el(2_U}2h%Y%MZXna-k$n9(2!h3T!7!let(?{K>rf8s0@mAA&OX2O}(pvKT7;>wF2vuaoE+V}IxOd`jfF|+yd5=#G&43LZ!{OB^Ibgz)m*|9(k3Am_eE>L>E;}L{AzqxxXqX&~KSRJR=c(@2%2k--?K}Onec3p|aVu`csuGjFJt#;4}hY@t3cho;VIUV1zx$glBF;sR!0_|-uJW@+t^$KXHwn7bxCCiF~9!;`SC|QDts-Jln0f$p@a0xp0auQA}+H#fWHO8Ne>eBT9Z~2QX1XO#;JrY&s@TSxXXWS>Qy2@~mA0Q)7WJfJ`Tesv{;dfcKc2hNI1e8tMnU^i<al#+kIqjtKlCXMhaknQFLHidmdAXnNlVgw2#*kKq)BgTz=VvG+pHJe%IylIdFkRgu!(xMZWUxoXD<0UaXB!YN&+H3Z-;Aq#om_L%<bzl#li3XPeMvkz$5Sv=a1>R1cRntZhb?C=%vkC%pCyW*ER(d^tWjN>V%;NP<d5K{$!s8`PGK$N@42cdCkNwx)nSLynS<fpB7G|89L<YXN%3=bunCHmB9{}28>;C38L+Tyv|@RS1?TRr_UpS~rt^kSG*`<CAx4bBesQ6W>ldN?MLsCxooSMdcGhk|qzcg}%bHdzF)hPc8o{chpA#4|?}YGaiL@@a<guk&Iqs8hlmh^gvGteP>d)&M`Ab3U)}du?MlUlYg+`#K^k2nVoyj>EeA`Cf!^vJNb_u1K(8(1p76;6!^lIk4%G2zXnPBu-Q0WG=$&jFK6PTH@fs=oaw0NZxh4Dy<oM5J!Tnc$9VJ+9`s6FNTsZyFCXXmZke25WkbWg(zYkc^UH<LL-*nV1JeD?S`mVsvdKrcB{0LEl}a(Mb)f<U0SwD0b{U>eY^43-`*g$8uCY!2tEF<(2$@;q4FJ~+^Ay5g1r?hjIM>|xRVP<tcGNk>L@tOE_w(6ycS_s__FV#1i0qD|e4VHc^ipW(8Pl8~ti2Og;N6A;Gxp}Sw!|AOF`$6$01<{21JIq$p-Tg;cdR7<|IK5?UiHF%QZGGY2~ap}kmO|}n_KgE<UmsbJw;6zofv17(Y0-BG<=uaD7{+Pyw*{IBeff^rEn4o&6V7j`mGE%+LIf2fOWkIXP^(`xl0?<%h#uJxTS0uXF3(D`zt7NTaa@CPS2y?)hR!$PPhz4W(awG_U-O2r`=*y->MX7Vs#Rb0VBXWb)Ms~A&vDs`B6%BpO0OD3YJ=>;LtG3QKL~JdR#=@47IyDNMDU*shz-DZW8>-uPmBognZoweHGds-7CT(-lRAcxqGU}!%3p<;${0+9k#Y|BHa5!gh4eN!iM(UMFciu65Xt(r2oVv_#r(H_b3{!pNS+NXBO*t^Srn@&a!f(r^F`8du{zsB^@jPME=rUYIV|2u*v3<;77yMdq@|U|@ZUk1iRod_5R@vq~DRI5*=w12bGkAZWL8<9~BWHrT7Jc#=eDWFW;0!40AettVFQf74#*&&DTrBjloCXDd0L{Sxo&e<$K5+vzo_rcmO0<Acwi23Rv&#IGO8(ZW0(nb5%0F(iys*tXR%g{_!`!gj`Js&RlG97NHU5v?`u=2l{|VdP`1u~zwp}or6?Watr2dDp$hpe8#m(A&wQV(ewcAqks&pON(H*PeTVf>ZM%Ok!g930DSA(8(=YzQ%{s9Qg9(^p=#71+F8A!pWedl-HcMd-7JO88EcUEP{r+w#7Hsq&$=l9%q{$yuvu`@qy@&0icnV<G^KiQOj#5=fKjK$zjB_`)jWIH<ev>lDx(ZQ$f=ug|xf9l)O!N=K-4hq}RH*~dZ^QLUrgWm3FDI8{_Q_nNcE~X?g9ZnF{84?+)&KCG>6a4lj_%dUjm03^a@B<V4;HLP0a<6=_EqXke$K4|zX476h0r1J;^2y=yY1973LHvKp8|?2M75{1T{Zr`sCs)ZIN9g;X-DbS|(fuobrkm{UpZ_Mi$n46C2(!6p@2S~K1&ESc)-*Xe4Ts5;avKt0@^$QO@rj6{nv<iL0k*ti^pUNYY{Q&4X)t1Po+F|IPmRFcSoCOHle_^=$3iBAkZv6;cvp}SsD{xr*_!Bgw;aD30|EO|dYTl}i74c&_q%Wta}VT<B1WYdNOn@aI9!>%MADoUD5y)k!<t>C4-czZaP4ho1Kwv?YOXQko5lNXiwuk!=gYJ%ADBS|61;I--Z95y3BPD_(>(ncDRNH99cG`XH~h$xuaxTg6ujxopc36H`=iZ}@nY$+X~8pe;GMLF`)hOap~~4n_obQALL<va&^2JI<tlwKS&b{OPCk4DO1HS_SQf&ZoxWd8(k<TasaztTp7~ub$lsu+utiqT3wWkQ_JZ@|h<~AoB0J?)(1!7X+UC((+NFuc-*@OX-`cSAjfC%*m2%^yjQM2wrqq<t6x3g9aOYv)eUyZ8!oB9ikORDZc`$(GayqJ7>UF8AN;e(VcmxFg(O>YpW5tEF2z3=cOE^TlG{$)Kws6+Kd-TST`K5rn#om0${r4P!og7)K<$A_k+t_0uUxapSHUz?_AfcYA4R;M_oEv)#Y8JlSE6uoxq*ymRLSN4{sp@0;E!<z?{n*qB5z%*?v-)`kt>xbg+OIWefesD%Cj%!FLQy}F_?$%81*b4(U*ffhpVO5y{LfA%=;dM>uG7g7WHyZsbD!#0rEA)%z#SWP3K^rZ8?eZw2}sn))$ai}iAwHJEzP>Or1^n!Ih!r)y5Bu{c?>=iqk|qsl&F2z-c@-MIelja_M|j~GMyf8Dx*I%ua>}2O!r2qEvZG8>ySWnc@{?oP&l@@Uq|#5xg_&=&7=9$_;Nf?SLRxnk>1dob($>8n-U%!^Gmkco8HaY9T)??Us^1H{=C$P59Rxh2jOaPsTP1a=ZL$w&B$hK!9~MohuJ;R+xTJykEb{Xm}wV|Fa>mxHMDh&ce0C|tLGV3yYH}@Nfmm~D*N)ax}cfT{1zI5HdHu#s-$bYu2r8#dQQ|4h81GMIyObrw1FAh!E5E0QU;j=UgDozYCvQ{o){3ns=4xj3*im^QR@H;VtM$ZCQ?k6V5SekIEKDp0>etqAw@lAx;iV{<3$}UL!5aBhF4e9Hy7U;fiuNl_nqOujqI1$uh-p|*bybIs+u`b%qr-P_-aT^h{Pz|@MZIPMK9@_@{S`6??lIx!Ne(r!-#)XT+|tb2&uo7a+fS2B>qwJ;!5Sv=<Z<rcV<%&`&_7$s>;ra=zH22Ji?Os(d?m>;2u0X)A=~tfG+0aX7ML<*`g`qAscTs<zXRVUtUw#lJ@&1&D7{KtvJQ@vaV-^_IAj>$c?N6v4X*jn`VnyW>e}u0JJzNd{xUOz5P%T0|ec4?t`^LUukSvas3>KKqcp0I0q2#nu6ElTB9`bH;Wp$1cOP`DeSLIN}UF3wH=)oSjAEllgmj8@Wka}1W?O|pZ5^zO&a^Jkp>vx=Hr1^)}CkKSpwTxZcgiD`kn=nsd;`kb!3-5Z1v-aojRH7-(Yrcxa>mn4XC%yn^5BFt)pn{%;j@f?uOg7lVY%H;R3imt_XLOiW39rXg<V@t98zi4W@e!A3b<-(tmRI!F{^F;a9zfQem($rLi4G5v+l~!UciNU&^a)Cs&Kf^7>?kx8=m*4d(r&nEre7=vnUFg?N{WCu4kqS53_Bz~fwT)FxmV8UneFL1}w1n_i1om-uQpg(e=&=PU7aj!*fH>C({tLVe$d?npeI;~SW|*umHN9JQI_9|tF`WWUpFxq`pl5*eVBFNy#*N=gwe33YL3h`WhLFz%+y4QHH$^pMA*Xb?rdde$+?(NWn#@Zr*!Y|5ct&XC%4p%p8`(JY)bJ)FR@tu<W@*V{AS`5|1Q?|%8lZbBVdgn3K9d2)IX&|NZl2Pqd7LO$nop-ckLS7TTKbJD!DG+icCCOfPQOWh?@DnI*0`N`eChpH1mX^I*@%t=b=#o%a|l*`g>{#?svc0?DI47kE9WG(5V{Cnv&S2w)wYR9Gr<K#+f9{ur-iEL89^WV-5LxNeqVqt}rvU{HLyq-F|75gPdgPhrp;jScJUY}w7VKHE0=jmkZ3@%4DQn0J^hbZ_uGm5oIAc**qTOwV-@-|X1A^VmCf9;f{{g-y~OFddRe;ojA#OR?A#p?iQ*Ckh|a2){ci{=XHne@->xL88J4j?O<6p9+|1vrBhJ6~+~I|206`Z9nCDwT(3m(|{IXMhQgDJ%bL<81}lU1d>VKrR5t%h&ls-byiH%yIXOY8hvRbjW(^G@F@2gubeFyT+_&zH1NE`vbD&dhop6`NJ&PVw)k;983%Hp}sO7X3KLlO+rDVU6v=Yg1};gO|t=$6eSxXlM@U$f4kB1rTVXUdCt=K3}i!*vo*I?RzW^DRpQ<*tpYtWw!ocW8gzVyES@W?c#*X7^0~1A#kr(4BA%Nnao>+tfu7|Gzc%<JwMxQ4MRRR$7oVKI02K9F;iD_u!DQrzGpLMApx?O0;yG1XFc(|?{EY@lmO9UOQdU<RDAPf>Zcfa)skIF%%+@kH;6Vz>`{5#Wnw`q!<|`M)e3{nTb9VM*OBt-fEL{RNSah0{kyVIkot*PCE1DDHPSFdRD{;=ZYKt!n{!z9+d@s2Oqw79(jHyXw`^5RJVKf(A+|i!QD7vn;p20Xw@m6=+8zz3k_d0$fYK=PXXw(ckL3`x8p&N#y*ll-`WauaLW@FThlCaqvx^CPG+wrg&4CA)S>9Q@aq^(9HsE47~4u);tABN3g)9ZxoQNtUBLA{aqLEG<mK|KzWMmuQu&A0<4TG7ajhY>vTOl>tv+5%iVje0ZcG~HG(bX#87XaMewcGPk^L1P%iqo$v<8trBr)?K&JYWnS<Qy;m0)EtFT!_<~v(w09=k}yi@iSG@=Bp3lT+x2MV!~b3kz~bh}Pux+v>2_RiIBI$cbT<m3pxN$tZpYYGv!tz2kTgfFWC-1>H=98+Y<Qm6i9^pH#r4s!9S3fs-f`n_lmwmO(Cake1@wLBN3Hs(Wo)Ze(iVX7y%Dq$w!C&@7)E~64`RO!tl&rfXcV<0-);NtI7y&rs}n}yuoJa|b`0zT-%M?_%V^kaHJV8aVAlPhm3Y8<^|%pvLl~C&sP4t}A&!h6h8?dnilA3PYd8!>p${l@eBaboP{xOGtKo%S(~UZTS0BNkje<tvHvLWzdu{0BC~D!zL_@#P9t9C_X0zVx1RY?@FiygJTfKYt&?WO2C6Z--?b=;s-oY~YwWmJu@JT~`(!eLa`oza4P4!6=pS08`Equ~epS1BwpgswdWtkp6di+G9s)_kJsE_t9@4L?$zq=E8wbtOd*Jy&+bJgbquhs_D6EFGm^z!Z6B5if-Toib|OsmtZLtUSq&)lyY*Z4euy7d5_H}&Togc;>vwy?}!J?q|UfBBoQ!^zj5r=2g4p>7+WfA+=bv!DLv?(|omfBvX;RR1kJ5AgZW51aGFWOn7Pr}HFg*#@nJ$n(puX(R^^?j6h9rO)bDF;E{qefn(Br$?VIeb(_a8qsG$pD}$#_&KESL-u`0pCNsA=rf?tHhs3}liC{k=Z+b*`zOE2P=ne4#>EpgfC_~Z0eUVV>H-+I&Hjh4@C06Xbn*sDd(9?(`1pa(n_j-T)%;n48zKu6r${x2_yZTpt82y+Hu_<E(<xh~;8{aBXOsBonmK53{JF#U$%ItZCil2XA1w|uJxO!J55sJy>G%})quJ;xUg6%1Jk1ZeR~O!Q;Qe}r&3^-mF}!~WD=A`)otQsg%p{(!%b#ckwYFXCUpkv$>4pg~US8<>^yb-Y{$l3(_@Jp$0A1Vo5c?NR=j%9<2w>M1>0~jU&+-jpH@Q~tb_BTI5+o529lHWhW=w-%o_Wi2)m9&73clxM_<4x1*Pzi@EyKsN$!LUR(;D~u3@<8={dw*!!_3=nc`flw($mB4aOVO3#4e=M`HOg#D)l<q)5o;Oo|ho?tiZ$da5{<b5GrsLb`PFCO49ihtK}v%szgyZjn-2<ayxl0g58`#z5p<rxw2JPyvD0&oUjm++GsM1aesHYUpe^s)A*M2w8p>eBf!EQZi2gRRNs-P5P753;D<)21oBm_$@3yYEJR9NnwNEKmb?&Ij+CdnqnZUt31f=(q&a|Y{(fwi>@1I;fx0}apF36l)jcoVrtR|L9<#4p>j3)3A>h}&tv=g$@_drg1=WDjxVD(Tz#E1MX3-&wy0<8QhytnL3srDy2$-Yke7>v@w$^O{z_I=kSh{6ug6iTyRQB!Gp|PMG7kD3ymldQDmd{-r&b*%nO!-I)Fp_74hh>Q2M^h25nFW?=N`3@T2H|uu4u=%#X}^8*Pv5@zXK&y9%eQa-)7v-y?(Lg@{r1g&e*5O{-oE))Z{Pg=+c*FG?VEq`_RYU}`{uvAee)mQzWLj?Z~oicH~;bNn}7TE&3}FS=D)vv^FQ9c`9E*p{Li;<{_op2|Lg6W9|_=(1oKA%`y)aAk%0e5@PDKxexz1@q=w-0?=xQIJxa2)X81Q;g4n2RIJid<6v(Q}aCVVYC?-0if_3}0<(W+XakvDg#6QTCS&g%a^||GpR|}7<Tb6rnVj!38C#xi`!Awi8D%6OB;gu~@MQ>w817GJTB=>g-iCYBHv3`oHw`0nWk+06({QKnQ-!FLLv#5S!wvAlE4~pbm&T;p504wl-Lc%y#F2fgiw6-YB_zNk|`0srF4^iLx(yCKH4SxVqhc4ax;M{EIV_~T|8FQSQdICKqNF2QfM21DUS|v*i16l5WS2=t7;%V*R{Fc*&uklm-_KQjlf5OL4_I0t%gf@Mx6d`6*RjEa#b>u0Oj)l%y>p?ODO>=>NnAnTPwTtC^y-0IgOlw#bMSr!Gl0f9k0!2h&buHt~AuPQHtVGZobVfooRvnOMU&x70HT6BOGK3aIgcfB8Ekys#2%)1Bom2v$MTXF#fDmWdTu|RHUS@rRXBk{2+%H@WCh-*xFB`$y5?AJm{R`bK$cue;XdSr4A*Jo^D!PDH8Kko=uY|Hna>!ZsuzQ}{Bb-u*5<;mlB)Y}@K32+r2OE5ir4Z6tmuj3d?9N#AV&l88P8t6dW#hInFJqh{q<3J>cVr<N0+45v`2}imUZSCWy#phuV<f?RCb_}9{Vc?{sF2q*R2i%abu@kkuvo>IdMKQx?<?CWTtk@z>0&xrRrb64bmk?u0#IQ}y^~A*lw&_C2g^d0f6J}dpQPIEQf)i?l`stRu(LC~f<rJMI=2tUmbY|01bgJ{yZS*VJQ(#3PS0Wd_xCA;x*}>8*nt3$YL4t)?@EX^9m1ktg@bVNAtE_R6%5m2lojnsr=)Dq2`11z4)MecX&+!pt*2AAGQ+ZdmLY%ZCuH?GYCD%OrKi_}#S&D1v}{GA)W=D*I;2!5n@mqCP)LeK2mWLkOq7z%EzuUT%lfk7vfIZgWQU{$e%sIARemv^eE)2EIh!wjzf4!_=P$0Ve_;2Qe|6{XFTcL`tNRZg{`%45C*OSgo8SKKuRgQ?;wOLk)2I6t=kr_DgWB!x&%QYP^5?%ed;0YJyTLzs`ReswTTfR{XHS=kX1T;vX|xR_@Vm|XQe-MD3Hn~GQ|C#6fK-fYvv)yuW(~R^4+Um?H<>NgtE!b9sRJ>VESHlwIizz$-3`$(JY{gvLCj{W<Z{`LQ&>6WArkA0LvrdA?e^^CB{bF_hkZPMNXdo)>B9{1Lmhp_B-#_A&2azeRXp4Wn<Fq~A*`iI@~qPGoqX(!w1I?nOL((WiB7>hS1gKBD?+tu4aGswO=bsf!R*M>2*(z<F*mmI(0)#`6h?8_@_C9c&7M4qtnav!l$nhly1pC-Og#`PU{;V-S!EL?nXNAqU^>jnrZg*#v5KBMIYNa=I?!`JhH29BYk(3bLWZ1EFln(i9!s6fbkDpD{l7u58yjCdR2Wx!Cy$A{IQ*)G4}SIF_+)U>KXT;g>&QE-7&#0F+DSg%c^DBi6w|}~$pzRd$-ZMm1UH$_XrX70z;oJH22d)Cl*HGu6EAxkALerdAoGAo%P|j4R!;aTN@#Shun?{?S*%u(xT+7!IdDM--B1#!<#F-yjq*nFXn|eS`moB`hc-;}if<iY8xBh{6*DoQcTpr4Jfv(|IWCP>ljkCnU|}bL!Y>s1FzETckZt}L5`hMWeO9&ToVY|mOh4w1Jew2^2L2pV$5bjYOyc_0XoOCW`c(vC_LT(>@kgWSIPew<Ju?-0CJULgp91A+CqF0X@?_oOPATUa)tje!O=yb+C~-XtFDKD}q<xVysT7{RW?z8rXLy2|;%`RC%=iVCt%UET@cH+UdF;>iU-r3#q(*nzUlfvjvA$5ry@Dx|W-(e>7{^%ZxpL*C>SpC`FeZ(w;gQBg^|;C=UU!SDQigzVjTu&NQQy2$Y2t(<#L%P@(>pcF=qFYOxzO#<;LbqBlCvEoPDf;4k$H$8Bf|hH%JxA)Em?E<X{snO{HT;rWsE*`QZp%ug0^^x9q@NqyvmiMtRbNz>2qZRII|wKRUcv`Flj~F=s^{n;4BVuqk@zlI&;mUu9T<w_ng{ic?n)E2<vk*nKOHFzFvu`s;-?Jwfurvp{5UuYlq{MwnOLOMN>GxvtOSbN*bsWzhFbj8cun4RC`twFH=iO8<O4T##$~Rr2$kpyRKYuy@oo119ZhC^PMM89-<Kb1%7n#<E4F0xm<W*z#*K1z6n!AQHk))Zfeo{F+<7F^Ofk`1|H9_vw>wR)W%_@0TmrrhpVvQD6T1~)=khcH8Adh74tpfSy0hg)p#s|sVYG=g}&h$%wX|EPxM1uJzv^cpQLIk{^8Mv!F>3AE)4(z$r*5?3#A->WwC|uJQp)dm}y$uVRo1S8H0n$C29om#>8_~JrRcS9j~h*>3|lNtF%y@5EPDEWw|Jz$(Q@X{jRl-f!^rg8R3s`nS}eV%foZ|HW^RNtM&RB%^BVg<%w;V8Xn|}RC;-asPTZ`pQ$}oUlf<Aa0#t(<^aY(?Fm?CI>FSHDn9$1;HW6(Y@R}9fMVAH${@@S^?tZt9B4DGHDV|DLj-XX^%F^cd>zw!9u>3OfaC`QGsU7TfVP;4Kpo(3H;qWCAVsOC?73;~ofU1<JIcHa$`>2ckaOUhq&P3qHF8E-eT_Q`!*_MPPfVK8h8`6!T+o=R!2A2_=LI<U$S9h0jKrNASp(&QX$)cjB|+6fMpUTCS|sLzAt=0%jAnc(xXkpD7&7mf8iCAbuG&n9O08ac<b-1ENHfd<N%|sLR){xKo}bLl0bhdM86$MeJIk6GV>+_zJLadRC5z?!xvrcEqMY;dKD_KguP47RmdcONDPAK&r{B?Fs$a#!b9CGl&)Z2nZ{qaH!YGPHkOHz?sZ^}^%gKyc^4tihS^-!JN(Y!t&R?4h_fmW3>RR2`&|H1M`5ON^PKiUJz`UIM8Eo_7^loMfkvzH7_G0p~NyoXWv{WhzB}meal=%;+iFf6)Qj$;<EiE~ODfVmwrAnm%i$fF<W;tzuJ4>YpB6FBBuzYV%>6ghHghNXy#yxb#`Z9ASf!z?p#gtav6;ZhLXQQr?vjH;KL|4^_)nVouakl>O^cR(EMwHk;B`WqDw<(zOu{d>%DnbsJ?m^=C?SK<e9aio(u^s@_`dp0YK@Hu2p#bB$8{rf-k&WPThrW<Blu8vL<IlWyO^adfvH2*nG|?Guy2icPG%pA)g}*AL=&C%0O*n!)Xb{<UiOVCKY-f73H7%4d)kZu4*UQOk+d;{jH*Lik<?P_onF95^nm_TR{Cb`DT$%urfKWY`Q#yX6ANW*rO3QPkWqF#Aj{Qf!d-&wRp!aR>?!Dg8y_2Fm!V}DDcwm;Y)=nCMm-xdVjH5=-8r3_ajwcV#ki?fU5}14@3YW`CvK(Z-FEt@hS4lUyoP;w9RXCGn&&v%<QC=Qc6Lq$3nG{@x#Uh0uJwrZIalTjc31mB0B*H1%6vMM{j9x9L?MGPOW#lJMJ!%B<i6b}7hGm;(Y#+e1n~2mk9AE=2PT2T5VtJ>U$q}m1hPPl+6PEelX8nBKUY_T_^#>yRKBkVmy8fY-gy}V)SsSlb3wEy2#$pe?d2;e-@c86}&WhOM=s=uJKS+~sdhp!0w%6|6dt$DghSL>*P|DuDfBL{&7E|x*WqUn_)Sdos{a0ozUb$4hfAZ+b;P~!WCy$>LrW{L%(`m-B-)O|`#1HGkr0&JdW)!u&X0wsR(I^T=^>%xdv;%nA4BK(o9tABog7-ljxdAleU_*Bw_KpXSpY)!bFl9LKnr^e#>EUsg)7DA9-aPHI@6GyAtAC8&n_lBI=%2KzMKM~xIypY|-OdSBa*tcbt!A6f=CoR;r|wZe=W9;=dan*RoD*pZ7`Q?6s7{A?8qNNZ9~_<F_hV?j5%_c*=jgcY`X~LS5rdZ3ZhJxRlvV2WPW<B|{O-3Jr$?s&bs-3Pp5NdYe0%cfF(&W<;dgQmy*BNd>(;!$ssx>mWAEK}n*}=cdPm2No=ccDj$4hM=Mu&zEw_2pXa}spUcKFP+XgI=IPPh)-#en?OTBjQ<TUVzI6<S|Zu$*E**osE-QH3AoN&lf%7=02AGN7g-#<QX9QUc+X8SmB{T>^FR;zw;-0YZfI6gXRc)<}Jbm{|jJ6?-=QE#2PLA^n}J88I$dcSp4B-NnPz{8hzP^;HG&#J&rhq#yD@%%NSxyM@aVMM&s4&m2!8*Sh3P)kS6e*N^QPlI*RIcmay(NU{Lr`hUzO`<}xbLs-MsC)-`&+9R&9l8A`bgs(VI1cLVUXQimdO<^Q5sWml6!oUrtoPf;ePYSBcXZM`ZWFAaetdG|o>H04(Q&`t>M^RgougA1%J4Q${LWFU(`RFSdUWEq1LDZ~DU>|!w^)1ie$Vaq*$AF=ync)N=l9xv;P+^50b|#DP=WAh0bzpUo@k>JG)`a^(qXn<&~W>$7BTHnz25NJY>baio1OM)pW)a#sn?HAsZYnvUc2M^Z8nPiUaQe0TwULTb-C3RZFudYcD)x6t-TZX$a5QvXO98fV>aiTcr^IfWz)A=@3k9EpWzFP-8-VO3EaNd?|6)EUfc8ffgF#XcXWCZ^jy{tx7TX<RHyIxN5FJ+K(F6!^_y;w;qC&Uz$Jb@Zgo2KmgjSEanfiqTwNF#m{oPrhTG}+eb*(ryC)5RR;PY=K<aker+zg2qxw<*i1U@(ulJ9rJ^$o5==FRy9!H&izvt69wF2)1q*X(-0ib~APN<LVpx10Q*mwqhKWGOo<DY)NUH4eqo%+$q>FFuK?fFd@h7;;HJni%vr+m!XZaX;js(a^#^lmkl^RvQpyv26zY#w`@*!dHB?D_Xv&bHoqHJ&dgKhS-dkCNZ7Crc{&nx~!wRj1(%p8J(6$~a!NW?ANOnJk;H#g)pH_2rk=jCS*{tS`Q>Dh)hKG;<ub(SOSS@$8{=J<TARUoJ35D>ee^`U>yY!<ZI5XFA{Wq&Jiyy5(=b&j4fc!>RSHZ-LA?fW{bPd23<I*KRF*fiWSt5u4BW?Y1z3IBOd{M|j5JbIT9*3|<*zwwABxs#jGD!#G}mc6MO7O;GdMS5L`+UdNni8L6vQ8v`Y@CvHHo6GY*La`4mDs$S!vM7=IP>QLQltn1dZ$}f1-2FI;+j=9<E@WCFm>9?C3I|@(%YE-SLYQ>-qgXL4TE~*v<6Rbq^a*iw-NpeU7gqDtTf`>Z`k38iF4IRa(B!Jq8#gzPYf_N%HTPtj&GNvwI{3(7@Rv+v-b@bfOKf|CvmpvV$5YLnr9;s*FE<@ZJs)W$Mkg&vW5q%rdw+vZ4cT^$TL!}ao#zf{3kvt~y51AuaKCQ&)*UXKWED7&dNQ#wbXn@b*vkIO`xYi4>-BRRZ7|$Oj3o%d6%zSX}oU<7|n#?BYcrd;UakmtssIxh)UW<^s#z3)hQYBIRB8*uwvCRC*zZCWzuGoA|k1-Pw3s=Vy7~=)g9t22J2^`7Q)<7m#D>~2xER0v1$j~VY=d7*f%+jiWY`2GC)N`|k+{av)Kz}oXcRm_rvjP@51+|>uU^h7$rDT;OcLvb92=NwFJ=Zd!4Q;#j{d_X3TxB@=0>^CoJ6&->AJq{wv@x1om5hr>waYKsNIEu~QmQ#}%VHpy(54Gx4@($9voER=x_*UHS<MGZO=?D_N=7I8VCFU}XpO0tzLfN8Gm^S?U!{(ZTw}+f37#&WZ)2B3G+?iGTD`rEfK@H*OqJP@%x84K_c9NjyPn7sP4%YXH5lpYg*Rww4*1Ot{E^63TTT`eE)><1LDRr+6rTG$qcfDP>;jWBo@SfFOwg=t<tG}{SyQOSMB#KGqK04Wa$}mf#UOlPOsZI#IdaETp`dNB>}RRCpOd8sMRX3hgUjN{35&Oy;da)18CN2VwZl`Rd|!lZI$Ui}KP{T)mjodavjc2f^oY*ah7r4;Qj-`&MA3MzSw?atV>gVM*{NvCK*#U$(V2r^;+3uj<WW=7+DRvoc3E?pBs20|iz_0c^^&gQI#e?1NjW=EbPqj3Q&giJrX=U2(>G)AeGMdSh1V&@Me^qu7wOl#+t18%j^)(Q`M1!BF{O3+y-P;FHO*Px&RN&<&y~s4>m6tBJl}8@(6FsAd#*d_w`Alk-$MXMYC?YaDN}#beeQJkWQjL^m|gVBDh*k3%Cc=F(6?|Sgq>8z{XkhUv2h0zFVUU3m?Q`Oc=!lds8YUVN6@?yXmlC9+q8|<H^ixBDZk6QL0;Sn<&9|&ie-&AY>K>D*v#$wd_$u<T@9?I7X%S=f=At~huKZ9{7z77hKMbh9hq9Iabkf|wVzt{W{~sQbTUg=)H#`=u%5=r^GQTEB&?T{)ip??Bzjg3$2|5o>z;nI5A>7u>bA(w+T{-pUkak{5BHtVmanTDIykaLb){ND)k;`oZ>L@WuJR&gK$U47@_q%D=GN$g*Wnm1I~E5+^5bkXoe`MsDq_K1I>EH}-SQDB%0;;j;Oz`o(Z;=lQj|-f6l5`%rd;HfW>?-ZjkLaM@QpJ}>mpXuFAm9^DqqZtP_mU`^TMpINTQ1D*ro=u<&)Pdzqe#$Q-_ev@NV-Qt5sfRbbsyGnR<p95(XHQRAG5*X$Mx<%qa3diIsz=HXS_e9sE^z@WVM}EM*5zDIcw~mp_z%Cf#RrC;?d+w5Ld@U3UH~B|A4czGG)6F9nDlw5mJ5xqHk!M=}wmwVGqY<K!v?2AaUbQss&_RD-!fTWBISiqndpT9NmlkjDeWc21k(cyd|0VF@IO!|pkeYl9#iubp2>SdA^K$98f0POAeK|GGG|Z?YO_7r0bJd&-(m-7Bv1di?RyQfqojO|hms&P|B1`+CCu!a9<z74%J8B>1IpcqNoNwk)BxAOL&K=Ky*bTpq+ywQ_OtJ6vuDD9c;p5N_9cN$?RZ!`%%DQ}p#6Nx<{WzWB(O)&inZ9sv@!(Ox!~S12|RNiH+q2fBX0qPSa;hLMkAmFU4{I82CH8Z9S_Rms$5g{6UBp6EL-K}Aw{+-s|HpO0jX5x=r0lQ(S41TuWX85C`CS*o&^u3iy4v|aI4HYnc<>dI#EzHZ|k5VK5Zok6K{ZTXr}=B{0Cyv&A$UoI)K)~PwEWFK#_fZbU}g(B)mZ!^j|pdnp=BS=wP<no~P+Qbj)(FysMaS8cW%J}1>vIMqF%m4zJdzk39dv0LRZ3H>`y)v-NEBBSkBD*sNwNLbw&1!s-M|abRDX_56tCEpY2Lh|GArMzLl@3Gkx&(Gx0#J{|3cmkfu&bK0rG!t>B4vg}%HTg5iQo3`^x!|Q{t%r6ukQDr-2L|C;Lg{_rw42g<dv;d_yFT9N5(**4QGB9DTbY2s)Au^i_C@e^HP-)@4S9&RPN*=2jsytHQ{A~I-C_Qlk5UFeKjHHN<13y>sE($@6lHe?t6ESQGHT*{u%dYgs#nxYO6*&yfus<ascCCMrhg4Ep>(f?M!2ZuYjUCuzJL5*1%1~cUEhcNy_IIRFW1!;nqHJr&Reodzb4BRW(^#jLGj-qHJgP@iLqGP+o$f-G8#jk8+XxIn>lc&(3b1WbaXd6oLv-qX&j*v725^CdjRfSu<SGDnlnI9h$<^9Dw_3Y#kg(EDjd84-Vw55k<W@gGDHcCOF>P6eUsqAOpi~MI9?03uha-wl#|c+1e!0z&2<;MWu`}NtNS};Uy0=Xp5z~TyL$T-d&knV@zwxq5PJ&+sHCe@;0HLKU(o*5$gU|viT}PUPFt&RQX^BXZB5H_j}9lcb4JuLe-)SHxN<XpV~77g3Gd?SA@%p`OKTdZlfX)5K>ThlNeW>b=?+-H9<3{7;{GhR&>Jwlj%<jiJ26X)Y~i>!!Y)FhJ(cS+A_8;&i+5?m3qS{BLQw5zQ=H}J8*H*8khv23(<kYRk*sACmI?E^*<96%69*BP66$5y_xH&Cv&$_QgLx_vN%JC&vv9EttG<QV2wju?rEQnfT-6c!0*9mzMjQG!_|V=@ijSpi)|ZahMHUPrh8d}hE?-h&Fg^p(A92^xwMqW!d`n}?+$io1Z&*zB1fg@Gbw@%&+Hi2`K6c(QY)(tik4<>^U1Ou=VUd<F{WhA`J-PVL!QKJ7e*v5jOPhcHd%_@aCU8l>(v;KBSj%!*9B+h+%4v7e7WE&-kpuo?_*q_Ew4t+U2CmvlJiaLO|qJA3!AlM-o)k`+Z0O-yHB`?3z=2_5)TI<eLI|9@Neu?8lGuozX4D2BX8EK9Lwz0!i+*2f!fJSSe0kYT8$Dkpa-?+F)%o&6abS8Maiv?yUG~`Uz_ieB97KXz8E8vlT)jUmyUmg`^I5%Y`${5c)P9|PoQx~nNn26E1RoYf5cury~+tgwH&)SGxtclCsXqaZ`qr~JxN72V1Gy91f!ePjYo0Jd<O}%XWHF1w$Qa+Ea$TeIs0yt?7}5*H3pgs!$aT0FlZv#{-<(bGSAFK$yKwbl41DG>wCo@3blrTVKi_Qj;KD9XR6ECQHM^t#t!T#UFG~nxC6nO(R@11xKwIurhDksmb;tOppv=r;Spr}%iFK2&mkxx<xqlhHI2#M-B1;nv6hWU6|)=eG`$N`T#xC?<~O_Qxv1{w6Wlzvb+u^s_=ESE=Qj)c_^|W6WX>1k9>h)AIRku_q|EiCjY95jN?xe+lI<cBvKq!ovePb$xY3p0AtkWSg_np6BX6n>P>Jr9Z3M=&fa2JxdV$8qW%@yeoKa8L_I=5Bqd?s&SM#%hyooiV^sYFuavBJYU70DPbZb{YMdQWU>8kiguI<R=+p-i3ef0AO(l6eT3zl{P(1+pxj?@Po{dbMb<o&9ahkBm*T`xGV8fzK{JFDph-BJ;pzhPahPqMb0DUN1ok>Q~$k5cBRg`2KFj+IpwUAz%D<`gyAfI5adn^i@1nz5Q56|19T4viJYcrm)H%0T_{@q_!yQ)l-G^t?rY>j9JIEEpXj=iOvCx#nBH0e6>6!Atqf$}rV6y;4Ecck`)lVPI2QHtEY?yolV2(h{|O$n==<i;}lqK2GX_xWSuR+<gByl~?Z|SL$rKf}HA!Ysi&4Ww(&CcKA)?Y8&Q@$f>w`8M#tr(_Q4O8Rb55wW$r)kyAZ!CAm_^bR#+bd!6$-%bUrSy5@_?4S8xdTuv@eWG(o*fnRpNsJy^GXB-fvei5MZxamYQ-dkP-tlwR3f{<@U&aE;XadUd#o$oT|-%I0XZx}~=BLw6H<^l;+a!m7k>t*GoKF#6<6ofgfP#_?1EXo9YF<l(hQzaQ@Ny0Rg#+*pJyuPOJhs7P1ofi;eXHd@BNXxF$AEIS86LonnNcqwxnF<xTbe9=Ty8`&@KfrbHMPC%>0GcyAGiy#zD8<B~6jB3~tZMnI<a2A_F4xEFj||twlgnD%BZP_vlOpVBo2C`%37qgrx7>-t{14sII~jJ1!UjN^qlnik2TQ4Z)O&esaV^jI&iTuR_Zom2BCxfHX>syY+`X43;c^Qo(RS|QJq}m7U{9R%&F9Y=Ff{_*0_+wU&QtHJygpekK%8mst9o%hh)l*0<X-2Y5|E*>ZKkTq>}GOX6O&^vDo!pNBL~f+SEO#c32fo$WWI?#Eo<V{s+jj`P#nRcWn))<KDl(hdzyY;`FVFfn_fRnZ#h55>hK%ebAHa=opqlcy#1TMd;2&4{_q^0yuxyo+O3~E@Z%@I2=W3<v(ZNL>ShR0(C3F}n}^2@43|Qd5BxyoS=T9$U5SX?0+<iGNyKEeWkXI`ZoN%iFn7b0=1av%jgQ*a!VvfR&7IJX#Hc6duuk!!FoP7?BmoJ$v$4;d!r0zTNyEiZu0&OZy!WfeUkx7i9zXuggGa}MM<>7j=I$fPWybS<z5V+)|L=eQt@ZimqKqZVeE#{<+0z;3^+FKn%iL6*e4QJr?t%i3R@;I}@0%xg2B*Ed_lz)p^XS3-uQCv~DQrOpKt%>me)sSst1sSt>km$T`{Yq?kR{R43$YwG>lr_RySu}}DC{|BAb(vCSoWAi8(~eKEEH2cDD6&VSKq{z{WE};EEPTbGD*|$BH>xA*;{3Y13l`LTbfD<54*Mjr-m4kKb{I1Q&N^Qj1eM_)sryk7!p3pg8X)E(A-WTOi^iTbKGODjm`bp7SXUnCzN@y<L+m%7drzlPh2UJR&vR&Gwp_Gv5nmA-;lX)#NgYRd>2L+^rl5dNyVCDPC6`S9?Trg4YH`v*e)~cX0z)9&aj<k*$0|wJI}WFopC$Ny7!-XJ2bLm>e!pkLY@Jb9Y5KW7T9o2rl@J~n&szqR`>&VNMx4NL*b=*aC}19iE&wH^z5Q;kUK{DWSnRjSwij!$AANQ&=D^Ivijs_lHmche3*Ozn~}}xee?LqgI`%38&G8W5AL7d{Yu4TWWU@$-2c2$f6a6k<vDq3;`QYM^bd^;7)**uxetB3Tr*uS!6d~y1NeoAMM%5_o9|Z8HJ$63QP$qvgmt=_4a@`H4^76hUdB<AdgU^;=w>ID$(x+|1$LAuyPVyNSF}-L;@nPSVK>II{sK7T_u;!Fa+YqWf|VoEThlpniP#PyvKmONDLcTEP}_v@dKS+u>VhTG3RN!W-%p0&Geg4q(pXULJUp3g@X4BkJtdY#5x!g37*WpZ=cO@%+s7j(UNeJ0mg3BpwO-;XV+@$jHeL=}Iff{$*InEwdD0XkM}-VhQrs!DSC94cL+u`&X%F}oJ@(6ZdZ|b`#gR&9BL&h$7Q)w=1X27zRh{u~Ci*E6;10AFv7DK;#zreIZ2mtoIgq{'


def hc_module():
    module = types.ModuleType('bundled_hc')
    source = zlib.decompress(base64.b85decode(HC_SOURCE)).decode('utf-8')
    exec(compile(source, 'bundled_hc.py', 'exec'), module.__dict__)
    return module


def _patch_n15_password(hc):
    """Fix the schema-12 (n15) password derivation in the bundled HC code.

    The bundled code derives the n15 contact key with HKDF and only then
    folds in the Argon2 password output. The app folds the password in
    *before* that HKDF, so protected n15 files never authenticated.
    """
    original = hc._v4_section_material

    def fixed(env, password=None, hwid=None):
        try:
            schema = int(env.get('b', 0))
        except (TypeError, ValueError):
            schema = 0
        if schema != 12 or not env.get('h') or password is None:
            return original(env, password=password, hwid=hwid)

        _, _, ekey = hc._validate_envelope_v4(env)
        aad_base = hc._aad_base_v4(env, password_protected=True)
        raw = hc._finish_hmac_state_v4(
            hc.N15_IPAD_STATE, b'\xf1' + hc.V4_CERT_DIGEST + aad_base
        )
        raw = hc._finish_hmac_state_v4(hc.N15_OPAD_STATE, raw)
        try:
            ops, mem = int(env['l']), int(env['m'])
        except (KeyError, TypeError, ValueError) as exc:
            raise hc.HCDecryptError('V4 password KDF parameters are invalid') from exc
        ikm = raw + hc._argon2id13(password.encode('utf-8'), ekey[:16], ops, mem)
        contact_key = hc._hkdf_sha256(ikm, ekey, b'hc-config-content-v12')
        return contact_key, aad_base, schema

    hc._v4_section_material = fixed


def decode_hc(data, password=None, hwid=None):
    hc = hc_module()
    _patch_n15_password(hc)
    errors = []
    for decoder in (hc.decrypt_hc_v79, hc.decrypt_hc_v4):
        try:
            return decoder(data, password=password, hwid=hwid)
        except hc.HCDecryptError as exc:
            message = str(exc)
            if any(word in message.lower() for word in
                   ('provide', 'password-protected', 'hwid-protected',
                    'does not match', 'extra protection')):
                raise ValueError(message) from exc
            errors.append(message)
    result = hc.decrypt_legacy_hc(data)
    if result is not None:
        return result
    raise ValueError('Unsupported or damaged HC file: ' + '; '.join(errors))


def decode_dark(data):
    from Crypto.Cipher import AES
    import msgpack
    key256 = b'$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd'
    key192 = b'F)J@NcRfUjXn2r4u7x!A%D*G'
    iv = bytes.fromhex('232e39185523184a5723586242200e05')

    def b64(value):
        value = ''.join(value.split())
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

    def decrypt(key, value):
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(value)

    def unpack(value):
        return msgpack.unpackb(value, raw=False, strict_map_key=False)

    text = data.decode('utf-8-sig').strip()
    if text.startswith('darktunnel://'):
        text = text[len('darktunnel://'):]
    if text.startswith('{'):
        meta = json.loads(text)
    else:
        try:
            meta = json.loads(b64(text))
        except (ValueError, UnicodeDecodeError):
            meta = {'encryptedLockedConfig': text}
    first = unpack(decrypt(key256, b64(meta['encryptedLockedConfig'])))
    second = unpack(decrypt(key192, first['EncryptedLockedConfig']))
    result = {'meta': {key: meta.get(key) for key in ('name', 'type')},
              'LockedAppConfig': first.get('LockedAppConfig', {})}
    for section in ('InjectConfig', 'SshConfig', 'V2RayConfig'):
        decoded = {}
        for key, value in second.get(section, {}).items():
            if key.startswith('Encrypted') and isinstance(value, bytes):
                key = key[len('Encrypted'):]
                value = decrypt(key192, value)
                try:
                    value = value.decode('utf-8')
                except UnicodeDecodeError:
                    value = {'hex': value.hex()}
            decoded[key] = value
        result[section] = decoded
    config = result['V2RayConfig'].get('Config')
    if isinstance(config, str):
        try:
            result['V2RayConfig']['Config'] = json.loads(config)
        except ValueError:
            pass
    return result


SSC_KEYS = [bytes.fromhex(value) for value in (
    'c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b',
    '7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e',
    'd39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e')]
SSC_FIELDS = dict(zip(
    'a b c e f g h i j k l m n o p q r s t u v w x y z ab ac ad ae ag'.split(),
    ('CONFIGS NOTE EXPIRY_DATE CONFIG_NAME PAYLOAD_ENABLED PAYLOAD PROXY '
     'PROXY_PORT TUNNEL_TYPE PROXY_ENABLED SNI_OR_HOST PORT IS_PREMIUM '
     'USERNAME PASSWORD UDPGW_PORT PROTOCOL VERSION ENCRYPTION COMPRESSION '
     'DNS NS_SERVER PUBKEY IS_DEFAULT SSH_PORT HWID_LOCK ROOT_LOCK '
     'PLAYSTORE_LOCK EXPIRY_LOCK PASSWORD_LOCK').split()))


def ssc_open(blob, nonce, key):
    from Crypto.Cipher import ChaCha20
    if len(blob) < 16:
        raise ValueError('Truncated SSC ciphertext')
    ciphertext, tag = blob[:-16], blob[-16:]
    stream = ChaCha20.new(key=key, nonce=nonce)
    one_time_key = stream.encrypt(bytes(32))
    r = int.from_bytes(one_time_key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    pad = int.from_bytes(one_time_key[16:], 'little')
    message = bytes(8) + ciphertext + struct.pack('<Q', len(ciphertext))
    accumulator = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        accumulator = ((accumulator + int.from_bytes(block + b'\x01', 'little'))
                       * r) % ((1 << 130) - 5)
    expected = ((accumulator + pad) % (1 << 128)).to_bytes(16, 'little')
    if not hmac.compare_digest(expected, tag):
        raise ValueError('SSC authentication failed (unsupported key/version or damaged file)')
    stream.seek(64)
    return stream.encrypt(ciphertext)


def decode_ssc(data):
    text = data.decode('utf-8-sig').strip()
    if text.startswith('ssc://'):
        text = text[6:][::-1]
    outer = json.loads(ssc_open(bytes.fromhex(text),
                               bytes.fromhex('74d0f3879f9d47f7'), SSC_KEYS[0]))
    if isinstance(outer.get('a'), str) and isinstance(outer.get('c'), str):
        outer = json.loads(ssc_open(bytes.fromhex(outer['c']),
                                   bytes.fromhex(outer['a'][:16]), SSC_KEYS[1]))
    configs = outer.get('a')
    if not isinstance(configs, list):
        raise ValueError('SSC profiles missing or unsupported nested lock')
    for profile in configs:
        user_key = profile.get('b', '')
        if len(user_key) != 32:
            raise ValueError('Unsupported SSC profile nonce')
        nonce = bytes.fromhex(user_key[16:][::-1])
        for field in ('g', 'h', 'i', 'l', 'v', 'w', 'x', 'o', 'p'):
            value = profile.get(field)
            if not isinstance(value, str) or len(value) < 32:
                continue
            try:
                blob = bytes.fromhex(value)
            except ValueError:
                continue
            # Credential fields differ between versions; retain the original
            # value if it does not verify, rather than guessing plaintext.
            try:
                plaintext = ssc_open(blob, nonce, SSC_KEYS[2])
            except ValueError:
                if field in ('o', 'p'):
                    continue
                raise
            profile[field] = plaintext.decode('utf-8')

    def remap(value):
        if isinstance(value, list):
            return [remap(item) for item in value]
        if isinstance(value, dict):
            return {(SSC_FIELDS.get(key, key) if SSC_FIELDS.get(key, key) not in value
                     else key): remap(item) for key, item in value.items()}
        return value
    return remap(outer)


def json_default(value):
    if isinstance(value, bytes):
        return {'hex': value.hex()}
    raise TypeError(f'Cannot serialize {type(value).__name__}')


def main():
    parser = argparse.ArgumentParser(description='Offline HC / DARK / SSC VPN decoder')
    parser.add_argument('files', nargs='+', type=Path, help='one or more VPN config files')
    parser.add_argument('--format', choices=('auto', 'hc', 'dark', 'ssc', 'ehi', '1ftnl', 'nm'), default='auto')
    parser.add_argument('--password', action='store_true', help='securely prompt for HC password')
    parser.add_argument('--password-value', help='HC password to use without prompting')
    parser.add_argument('--hwid', help='HWID for a protected HC file')
    parser.add_argument('--stdout', action='store_true', help='print JSON instead of saving')
    args = parser.parse_args()
    if args.password_value is not None:
        password = args.password_value
    else:
        password = getpass.getpass('HC password: ') if args.password else None
    failed = False
    for path in args.files:
        try:
            data = path.read_bytes()
            kind = args.format
            if kind == 'auto':
                kind = path.suffix.lower().lstrip('.')
                if data.lstrip().startswith(b'darktunnel://'):
                    kind = 'dark'
                elif data.lstrip().startswith(b'ssc://'):
                    kind = 'ssc'
                elif data.lstrip().startswith((b'1FTnl.', b'1FT1.', b'1ftunnel://')):
                    kind = '1ftnl'
            if kind == 'hc':
                result = decode_hc(data, password, args.hwid)
            elif kind == 'dark':
                result = decode_dark(data)
            elif kind == 'ssc':
                result = decode_ssc(data)
            elif kind == 'ehi':
                result = decode_ehi(data)
            elif kind == '1ftnl':
                result = decode_1ftnl(data, password)
            elif kind == 'nm':
                result = decode_nm(data)
            else:
                raise ValueError(f'Unsupported format .{kind}; supported: .hc, .dark, .ssc, .ehi, .1ftnl, .nm')
            output = json.dumps(result, ensure_ascii=False, indent=2, default=json_default)
            if args.stdout:
                print(output)
            else:
                target = path.with_name(path.name + '.decrypted.json')
                # Avoid overwriting an existing result.
                for number in range(1, 10000):
                    try:
                        with target.open('x', encoding='utf-8') as handle:
                            handle.write(output + '\n')
                        break
                    except FileExistsError:
                        target = path.with_name(path.name + f'.decrypted.{number}.json')
                else:
                    raise ValueError('Too many existing output files')
                print(f'Saved: {target}')
        except Exception as exc:
            failed = True
            print(f'{path.name}: {type(exc).__name__}: {exc}', file=sys.stderr)
    return int(failed)



import struct as _struct
import base64 as _base64
import hashlib as _hashlib
import subprocess as _subprocess
import re as _re


def _ehi_parse_file_payload(file_bytes):
    off = 0
    l = int.from_bytes(file_bytes[off:off + 2], 'big')
    off += 2 + l
    off += 8
    l = int.from_bytes(file_bytes[off:off + 2], 'big')
    off += 2 + l
    off += 8
    plen = int.from_bytes(file_bytes[off:off + 4], 'big')
    off += 4
    off += 8
    return file_bytes[off:off + plen]


def _ehi_remove_pkcs7(data):
    if not data:
        return data
    last = data[-1]
    if 1 <= last <= 16 and data[-last:] == bytes([last]) * last:
        return data[:-last]
    return data


def _ehi_aes_cbc_decrypt(ciphertext, key, iv):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ciphertext)
    return _ehi_remove_pkcs7(pt)


def _ehi_decode_base64(s):
    s = ''.join(s.split())
    pad = (4 - len(s) % 4) % 4
    return _base64.b64decode(s + '=' * pad)


def _ehi_xxtea_decrypt(data, key):
    n = len(data) // 4
    if n < 2:
        return data
    v = list(_struct.unpack('<%dI' % n, data[:n * 4]))
    keyb = (key.encode() if isinstance(key, str) else key).ljust(16, b'\x00')[:16]
    k = list(_struct.unpack('<4I', keyb))
    delta = 0x9E3779B9
    q = 6 + 52 // n
    s = (q * delta) & 0xFFFFFFFF
    y = v[0]
    for _ in range(q):
        e = (s >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[(p - 1 + n) % n]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))
            y = v[p] = (v[p] - mx) & 0xFFFFFFFF
        s = (s - delta) & 0xFFFFFFFF
    out = _struct.pack('<%dI' % len(v), *v)
    length_bytes = out[-4:]
    decoded_length = _struct.unpack('<I', length_bytes)[0]
    if 1 <= decoded_length <= len(out):
        out = out[:decoded_length]
    else:
        idx = len(out)
        while idx > 0 and out[idx - 1] == 0:
            idx -= 1
        out = out[:idx]
    return out


def _ehi_custom_b64_decode(s):
    alpha = "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    trans = str.maketrans(alpha, std)
    clean = s.replace('?', '').replace(' ', '').replace('\n', '').replace('\r', '')
    mapped = clean.translate(trans)
    pad = (4 - len(mapped) % 4) % 4
    return _base64.b64decode(mapped + '=' * pad)


def _ehi_decrypt_xor_layer(encoded, key):
    if not encoded or not encoded.strip():
        return encoded
    if not key:
        return None
    try:
        reversed_text = encoded[::-1]
        decoded = _ehi_custom_b64_decode(reversed_text)
        hex_text = decoded.decode('latin1')
        if len(hex_text) % 2 != 0:
            hex_text = '0' + hex_text
        ct = bytes.fromhex(hex_text)
        keyb = key.encode()
        pt = bytes(b ^ keyb[i % len(keyb)] for i, b in enumerate(ct))
        pt = bytes(b for b in pt if b != 0)
        return pt.decode('utf-8')
    except Exception:
        return None


def _ehi_hchacha20(key, nonce16):
    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def qr(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = rotl(s[d], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = rotl(s[b], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = rotl(s[d], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = rotl(s[b], 7)

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state = constants + list(_struct.unpack('<8I', key)) + list(_struct.unpack('<4I', nonce16))
    for _ in range(10):
        qr(state, 0, 4, 8, 12)
        qr(state, 1, 5, 9, 13)
        qr(state, 2, 6, 10, 14)
        qr(state, 3, 7, 11, 15)
        qr(state, 0, 5, 10, 15)
        qr(state, 1, 6, 11, 12)
        qr(state, 2, 7, 8, 13)
        qr(state, 3, 4, 9, 14)
    return _struct.pack('<8I', *state[0:4], *state[12:16])


def _ehi_decode_message(encoded):
    try:
        raw = _base64.b64decode(encoded + '=' * (-len(encoded) % 4))
    except Exception:
        return encoded
    text = raw.decode('utf-8', 'replace')
    units = text.encode('utf-16-le')
    key = b'EHIMSG'
    out = bytearray()
    for i in range(0, len(units), 2):
        cu = _struct.unpack('<H', units[i:i + 2])[0]
        ku = key[(i // 2) % len(key)]
        out += _struct.pack('<H', cu ^ ku)
    try:
        return out.decode('utf-16-le')
    except Exception:
        return encoded


def _ehi_derive_master_key(config):
    import hashlib
    optional = ["configAesKey", "configIdentifier", "configSalt"]
    timestamps = ["configTimestamp", "configExpiryTimestamp"]
    lock_fields = ["lockModes", "lockModesHash", "configHwid", "configLockMobileOperatorId"]

    def has_content(v):
        if v is None:
            return False
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v != 0
        if isinstance(v, str):
            return v != ""
        if isinstance(v, (list, dict)):
            return len(v) != 0
        return True

    def to_material(v):
        if v is None:
            return "None"
        if isinstance(v, bool):
            return "True" if v else "False"
        if isinstance(v, str):
            return v
        if isinstance(v, (int, float)):
            return str(v)
        return str(v)

    material = ""
    for f in optional:
        if f in config and has_content(config.get(f)):
            material += to_material(config.get(f))
    for f in timestamps:
        if f in config:
            material += to_material(config.get(f))
        else:
            material += "0"
    for f in lock_fields:
        if f in config and has_content(config.get(f)):
            material += to_material(config.get(f))
    return hashlib.sha256(material.encode()).digest()


def _ehi_argon2_derive(password_bytes, salt_bytes, time_cost, memory_cost, parallelism):
    proc = _subprocess.run(
        ["argon2", salt_bytes, "-id",
         "-t", str(time_cost), "-k", str(memory_cost), "-p", str(parallelism),
         "-l", "32", "-r", "-v", "13"],
        input=password_bytes,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors='replace'))
    return bytes.fromhex(proc.stdout.decode().strip())


def _ehi_decrypt_locked(config):
    salt = config.get("configSalt", "EVZJNI")
    encoded_data = config.get("configData")
    xor_data = _ehi_decrypt_xor_layer(encoded_data, salt)
    if xor_data is None:
        raise ValueError("XOR layer failed")
    raw_payload = _base64.b64decode(xor_data + '=' * (-len(xor_data) % 4))
    time_cost = _struct.unpack('<I', raw_payload[1:5])[0]
    memory_cost = _struct.unpack('<I', raw_payload[5:9])[0]
    parallelism = raw_payload[9]
    salt_bytes = raw_payload[0x0a:0x1a]
    nonce = raw_payload[0x1a:0x32]
    assoc = raw_payload[:0x1a]
    ciphertext = raw_payload[0x32:]
    master_key = _ehi_derive_master_key(config)
    enc_key = _ehi_argon2_derive(master_key, salt_bytes, time_cost, memory_cost, parallelism)
    subkey = _ehi_hchacha20(enc_key, nonce[:16])
    ietf_nonce = b'\x00' * 4 + nonce[16:]
    from Crypto.Cipher import ChaCha20_Poly1305
    cipher = ChaCha20_Poly1305.new(key=subkey, nonce=ietf_nonce)
    cipher.update(assoc)
    tag = ciphertext[-16:]
    ct = ciphertext[:-16]
    pt = cipher.decrypt_and_verify(ct, tag)
    cfg_json = json.loads(pt.decode('utf-8'))
    # clean
    cleaned = {}
    for field, value in cfg_json.items():
        if isinstance(value, str) and value.strip():
            if field == "configMessage":
                cleaned[field] = _ehi_decode_message(value)
            else:
                dec = _ehi_decrypt_xor_layer(value, salt)
                cleaned[field] = dec if dec is not None else value
        else:
            cleaned[field] = value
    # embedded json
    for field in ("v2rRawJson", "overwriteServerData"):
        if field in cleaned and isinstance(cleaned[field], str):
            raw = cleaned[field]
            start = raw.find('{')
            end = raw.rfind('}')
            if start >= 0 and end > start:
                try:
                    cleaned[field] = json.loads(raw[start:end + 1])
                except Exception:
                    pass
    # redact? keep secrets visible
    cleaned["protocol"] = "EHI"
    return cleaned


def decode_ehi(data):
    payload = _ehi_parse_file_payload(data)
    if not payload:
        raise ValueError("Invalid EHI file")
    # outer container
    L1_KEY = bytes.fromhex("7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c")
    L2_KEY = bytes.fromhex("b2bc617c32d8b9eb1943a5ffa8051eea")
    XXTEA_KEY = "null=V5kU5+FFrY\0"
    OUTER_IVS = [
        bytes.fromhex("221d572349555f1d112133236b1f4a3f"),
        bytes.fromhex("5543494c53443e3f4a6a4539384e776a"),
        bytes.fromhex("374c2541575e4d531a3c327b75431e5f"),
        bytes.fromhex("2c5d1147bbad422b3b334d4d235f1a53"),
        bytes.fromhex("522b01433a5e8b2fc7549e1ad368e541"),
        bytes.fromhex("337a1035aaedf3458ca167e92d74b839"),
    ]

    def _aes_cbc(ct, key, iv):
        return _ehi_remove_pkcs7(_ehi_aes_cbc_decrypt(ct, key, iv)) if False else _ehi_aes_cbc_decrypt(ct, key, iv)

    outer_config = None
    mode = None
    for iv in OUTER_IVS:
        try:
            first = _ehi_aes_cbc_decrypt(payload, L1_KEY, iv)
            first_text = first.decode('utf-8')
        except Exception:
            continue
        parts = first_text.split(':')
        if len(parts) < 3:
            continue
        inner_iv_text, inner_ct_text = parts[0], parts[2]
        try:
            inner_iv = _ehi_decode_base64(inner_iv_text)
            inner_ct = _ehi_decode_base64(inner_ct_text)
        except Exception:
            continue
        if len(inner_iv) != 16:
            continue
        try:
            second = _ehi_aes_cbc_decrypt(inner_ct, L2_KEY, inner_iv)
            final = _ehi_xxtea_decrypt(second, XXTEA_KEY)
            idx = final.find(b'{')
            if idx < 0:
                continue
            val = json.loads(final[idx:])
            if isinstance(val, dict) and val:
                outer_config = val
                # determine mode by iv index? locked if iv in last three
                if iv in OUTER_IVS[3:]:
                    mode = "locked"
                else:
                    mode = "bypass"
                break
        except Exception:
            continue
    if outer_config is None:
        raise ValueError("Could not decrypt EHI outer container")

    if mode == "locked":
        result = _ehi_decrypt_locked(outer_config)
    else:
        # bypass: clean fields
        salt = outer_config.get("configSalt", "EVZJNI")
        cleaned = {}
        for field, value in outer_config.items():
            if isinstance(value, str) and value.strip():
                if field == "configMessage":
                    cleaned[field] = _ehi_decode_message(value)
                else:
                    dec = _ehi_decrypt_xor_layer(value, salt)
                    cleaned[field] = dec if dec is not None else value
            else:
                cleaned[field] = value
        for field in ("v2rRawJson", "overwriteServerData"):
            if field in cleaned and isinstance(cleaned[field], str):
                raw = cleaned[field]
                start = raw.find('{')
                end = raw.rfind('}')
                if start >= 0 and end > start:
                    try:
                        cleaned[field] = json.loads(raw[start:end + 1])
                    except Exception:
                        pass
        cleaned["protocol"] = "EHI"
        result = cleaned
    # ensure protocol
    if isinstance(result, dict):
        result.setdefault("protocol", "EHI")
    return result


# ---------------------------------------------------------------------------
# NetMod (.nm) support.
#
# A locked NetMod (com.netmod.syna) export is a text file holding base64
# (standard alphabet, whitespace ignored) of an AES-128-ECB ciphertext
# with PKCS7 padding. The app tries three fixed 16-byte keys in order
# (recovered from the app's native core; the same scheme is used by the
# open-source Pantegnos decryptor, internal/modules/impl/netmod.go):
#   "<n3t5yn4^n3tm0d>", "_netsyna_netmod_", "nicetrybuddygoon"
# The plaintext is the profile JSON (SSH / VMess / VLESS style fields),
# or occasionally a plain share URI.
# ---------------------------------------------------------------------------

_NM_KEYS = [b'<n3t5yn4^n3tm0d>', b'_netsyna_netmod_', b'nicetrybuddygoon']


def _nm_flatten(parsed):
    """Flatten a NetMod profile (possibly nested) and add the alias keys
    the bot's formatter looks for (host/port/username/password/...)."""
    flat = {}

    def collect(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    collect(value)
                elif value not in (None, ''):
                    flat.setdefault(str(key), value)
        elif isinstance(obj, list):
            for item in obj:
                collect(item)

    collect(parsed)
    out = dict(flat)

    def pick(*keys):
        for key in keys:
            value = flat.get(key)
            if value not in (None, ''):
                return value
        return None

    aliases = {
        'address': pick('add', 'address', 'server'),
        'host': pick('sshHost', 'add', 'address', 'server', 'hostname', 'host'),
        'port': pick('sshPort', 'port'),
        'username': pick('sshUsername', 'username', 'user', 'sshUser'),
        'password': pick('sshPassword', 'password', 'pass'),
        'payload': pick('payload'),
        'proxy': pick('httpProxy', 'remoteProxy', 'proxy'),
        'sni': pick('sni', 'SNI', 'serverNameIndication'),
        'uuid': pick('id', 'uuid'),
        'ns': pick('ns', 'nsServer', 'slowDnsNs', 'dnsttServerName'),
        'dns': pick('dns', 'dnsResolver', 'slowDnsDns'),
        'pubKey': pick('pubKey', 'publicKey', 'slowDnsPubKey',
                        'slowdnsPublickey', 'dnsttPublicKey'),
    }
    proxy_host = pick('proxyHost')
    if proxy_host and not aliases['proxy']:
        proxy_port = pick('proxyPort')
        aliases['proxy'] = (f'{proxy_host}:{proxy_port}'
                             if proxy_port not in (None, '') else proxy_host)
    for key, value in aliases.items():
        if value not in (None, '') and out.get(key) in (None, ''):
            out[key] = value
    if 'protocol' not in out:
        ptype = str(flat.get('type') or '').upper()
        if ptype in ('SSH', 'VLESS', 'VMESS', 'TROJAN'):
            out['protocol'] = ptype
        elif flat.get('id') and flat.get('add'):
            out['protocol'] = 'VMESS'
        elif flat.get('sshHost') or flat.get('sshUsername'):
            out['protocol'] = 'SSH'
    out['source'] = 'NetMod'
    return out


def decode_nm(data):
    from Crypto.Cipher import AES

    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode('utf-8', 'ignore').strip()
    else:
        text = str(data).strip()
    # An unlocked export can be plain JSON already.
    if text.startswith('{'):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return _nm_flatten(parsed)
        except ValueError:
            pass
    compact = ''.join(text.split())
    raw = None
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(compact + '=' * (-len(compact) % 4))
            break
        except Exception:
            continue
    if raw is None or not raw or len(raw) % 16 != 0:
        raise ValueError('Invalid NetMod (.nm) file')

    plaintext = None
    for key in _NM_KEYS:
        decrypted = AES.new(key, AES.MODE_ECB).decrypt(raw)
        if not decrypted:
            continue
        pad = decrypted[-1]
        if 1 <= pad <= 16 and decrypted[-pad:] == bytes([pad]) * pad:
            plaintext = decrypted[:-pad]
            break
    if plaintext is None:
        raise ValueError(
            'Could not decrypt NetMod file (unsupported version or corrupt data)'
        )
    pt_text = plaintext.decode('utf-8', 'replace').strip()
    try:
        parsed = json.loads(pt_text)
    except ValueError:
        return {'source': 'NetMod', 'raw': pt_text}
    if isinstance(parsed, dict):
        return _nm_flatten(parsed)
    if isinstance(parsed, list):
        return {'source': 'NetMod',
                'CONFIGS': [_nm_flatten(item) if isinstance(item, dict)
                            else {'value': item} for item in parsed]}
    return {'source': 'NetMod', 'value': parsed}


# ---------------------------------------------------------------------------
# 1F Tunnel (.1ftnl) support.
#
# Format reverse-engineered from the 1FTunnel Android app
# (com.oneftunnel.app, native liboneftunnel-security.so):
#
#   File text: "1FTnl." + base64url(raw), also shared as
#   "1ftunnel://1FTnl/..." links (older prefix "1FT1.").
#   raw layout:
#     [0]        format version (3)
#     [1:4]      flags
#     [4:20]     HKDF salt (16 bytes)
#     [20:32]    AES-256-GCM nonce (12 bytes)
#     [32:36]    u32 BE length of the AAD block
#     [36:40]    u32 BE length of the ciphertext (tag included)
#     [40:...]   AAD block (header metadata: package name, signing-cert
#                SHA-256 hex, version, type, created/expired timestamps,
#                blockRoot flag, lock mode, key version)
#     [...]      AES-256-GCM ciphertext + 16-byte tag
#   Key derivation (HMAC-SHA256 chain, HKDF extract + single expand block):
#     master  = app-embedded secret below
#     if a password is set: master = HMAC(master, "1FT1 password v2" + pw)
#     PRK     = HMAC(salt, master)
#     key     = HMAC(PRK, "1FT1 HKDF AES-256-GCM v2" + AAD + b"\x01")
#     ("v1" labels are used by older app versions; both are tried.)
#   Plaintext: "CFG1" + 1 version byte + big-endian fields in the
#   java.io.DataOutputStream style (u32 length-prefixed UTF-8 strings,
#   -1 length = null), in this order: id, name, createdAt (i64), message,
#   field-locks mask (i32), then optional SSH / inject / DNS / Xray /
#   SlowDNS sections, each introduced by a boolean byte.
# ---------------------------------------------------------------------------

_FTNL_MASTER = bytes.fromhex(
    "9e4f569a0a6cfd2da000b9de35ffe74a4e605c3eaecbdf477a13d709da233971"
)
_FTNL_INJECT_MODES = ["DIRECT", "PROXY", "PROXY_SNI", "SLOWDNS", "SSH_PAYLOAD", "WILDCARD"]
_FTNL_XRAY_PROTOCOLS = ["TROJAN", "VLESS", "VMESS"]
_FTNL_TLS_MODES = ["NONE", "REALITY", "TLS"]
_FTNL_NETWORKS = ["GRPC", "HTTPUPGRADE", "RAW", "WS", "XHTTP"]
_FTNL_RECORD_TYPES = ["A", "AAAA", "AUTO", "CNAME", "MX", "NS", "NULL", "SRV", "TXT"]


def _ftnl_hmac(key, msg):
    return hmac.new(key, msg, 'sha256').digest()


def _ftnl_derive_key(salt, aad, password):
    """Yield candidate AES-256 keys for the given password (or None)."""
    masters = []
    if password is None:
        masters.append(_FTNL_MASTER)
    else:
        for encoding in ('utf-8', 'utf-16-be', 'utf-16-le'):
            pw = password.encode(encoding)
            for label in (b'1FT1 password v2', b'1FT1 password v1'):
                masters.append(_ftnl_hmac(_FTNL_MASTER, label + pw))
    for master in masters:
        prk = _ftnl_hmac(salt, master)
        for info in (b'1FT1 HKDF AES-256-GCM v2', b'1FT1 HKDF AES-256-GCM v1'):
            yield _ftnl_hmac(prk, info + aad + b'\x01')


class _FtnlReader:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.buf):
            raise ValueError('Truncated 1FTnl payload')
        out = self.buf[self.pos:self.pos + count]
        self.pos += count
        return out

    def u8(self):
        return self.take(1)[0]

    def boolean(self):
        return self.u8() != 0

    def i32(self):
        return struct.unpack('>i', self.take(4))[0]

    def i64(self):
        return struct.unpack('>q', self.take(8))[0]

    def string(self):
        length = self.i32()
        if length < 0:
            return None
        return self.take(length).decode('utf-8', 'replace')


def _ftnl_parse_payload(pt):
    if not pt.startswith(b'CFG1'):
        raise ValueError('Bad 1FTnl payload magic')
    r = _FtnlReader(pt[4:])
    version = r.u8()
    cfg = {'version': version}
    cfg['id'] = r.string()
    cfg['name'] = r.string()
    cfg['createdAt'] = r.i64()
    cfg['message'] = r.string()
    cfg['fieldLocks'] = r.i32()
    if r.boolean():
        cfg['ssh'] = {
            'host': r.string(), 'port': r.i32(),
            'username': r.string(), 'password': r.string(),
        }
    if r.boolean():
        inject = {
            'mode': r.u8(), 'payload': r.string(), 'proxyHost': r.string(),
            'proxyPort': r.i32(), 'sni': r.string(), 'wildcardHost': r.string(),
        }
        if 0 <= inject['mode'] < len(_FTNL_INJECT_MODES):
            inject['modeName'] = _FTNL_INJECT_MODES[inject['mode']]
        cfg['inject'] = inject
    if r.boolean():
        cfg['dns'] = {'primary': r.string(), 'secondary': r.string()}
    if r.boolean():
        xray = {
            'protocol': r.u8(), 'host': r.string(), 'port': r.i32(),
            'uuid': r.string(), 'password': r.string(), 'security': r.u8(),
            'network': r.u8(), 'path': r.string(), 'serviceName': r.string(),
            'sni': r.string(), 'hostHeader': r.string(),
            'wildcardHost': r.string(), 'allowInsecure': r.boolean(),
            'alpn': r.string(),
        }
        if 0 <= xray['protocol'] < len(_FTNL_XRAY_PROTOCOLS):
            xray['protocolName'] = _FTNL_XRAY_PROTOCOLS[xray['protocol']]
        if 0 <= xray['security'] < len(_FTNL_TLS_MODES):
            xray['securityName'] = _FTNL_TLS_MODES[xray['security']]
        if 0 <= xray['network'] < len(_FTNL_NETWORKS):
            xray['networkName'] = _FTNL_NETWORKS[xray['network']]
        if version >= 4:
            xray['flow'] = r.string()
            xray['fingerprint'] = r.string()
            xray['realityPublicKey'] = r.string()
            xray['shortId'] = r.string()
            xray['spiderX'] = r.string()
        if version >= 5:
            xray['mode'] = r.string()
        cfg['xray'] = xray
    if version >= 6 and r.boolean():
        slow = {
            'resolver': r.string(), 'nameserver': r.string(),
            'publicKey': r.string(), 'recordType': r.u8(),
        }
        if 0 <= slow['recordType'] < len(_FTNL_RECORD_TYPES):
            slow['recordTypeName'] = _FTNL_RECORD_TYPES[slow['recordType']]
        cfg['slowDns'] = slow
    return cfg


def _ftnl_flatten(cfg, header_type):
    """Shape a parsed 1FTnl payload like the other decoders' results so the
    bot's formatter renders it the same way."""
    out = {'source': '1FTunnel'}
    if cfg.get('name'):
        out['name'] = cfg['name']
    if cfg.get('message'):
        out['message'] = cfg['message']
    if cfg.get('createdAt'):
        out['createdAt'] = cfg['createdAt']
    ssh = cfg.get('ssh') or {}
    inject = cfg.get('inject') or {}
    dns = cfg.get('dns') or {}
    slow = cfg.get('slowDns') or {}
    xray = cfg.get('xray') or {}

    if slow:
        out['TUNNEL_TYPE'] = 'slowdns'
        out['MODE'] = 'SLOWDNS'
        out['ns'] = slow.get('nameserver') or ''
        out['dns'] = slow.get('resolver') or ''
        out['pubKey'] = slow.get('publicKey') or ''
    if ssh:
        out['protocol'] = 'SSH'
        out['host'] = ssh.get('host') or ''
        out['port'] = ssh.get('port') or ''
        out['username'] = ssh.get('username') or ''
        out['password'] = ssh.get('password') or ''
    if inject:
        mode_name = inject.get('modeName')
        if mode_name and 'MODE' not in out:
            out['MODE'] = mode_name
        if inject.get('payload'):
            out['payload'] = inject['payload']
        if inject.get('proxyHost'):
            proxy = str(inject['proxyHost'])
            if inject.get('proxyPort') not in (None, -1):
                proxy += f":{inject['proxyPort']}"
            out['proxy'] = proxy
        if inject.get('sni'):
            out['sni'] = inject['sni']
    if dns:
        if dns.get('primary'):
            out['dnsPrimary'] = dns['primary']
        if dns.get('secondary'):
            out['dnsSecondary'] = dns['secondary']
        if 'dns' not in out and dns.get('primary'):
            out['dns'] = dns['primary']
    if xray:
        proto = xray.get('protocolName') or 'VLESS'
        out['protocol'] = proto
        out['address'] = xray.get('host') or ''
        out['host'] = xray.get('host') or ''
        out['port'] = xray.get('port') or ''
        if xray.get('uuid'):
            out['uuid'] = xray['uuid']
        if xray.get('password'):
            out['password'] = xray['password']
        if xray.get('networkName'):
            out['transport'] = xray['networkName'].lower()
        security = xray.get('securityName')
        if security:
            out['security'] = security.lower()
            out['tls'] = 'tls' if security in ('TLS', 'REALITY') else ''
        if xray.get('path'):
            out['path'] = xray['path']
        if xray.get('sni'):
            out['sni'] = xray['sni']
        if xray.get('hostHeader'):
            out['host_header'] = xray['hostHeader']
        if xray.get('flow'):
            out['flow'] = xray['flow']
        if xray.get('realityPublicKey'):
            out['realityPublicKey'] = xray['realityPublicKey']
    if header_type:
        out['configType'] = header_type
    return out


def decode_1ftnl(data, password=None):
    from Crypto.Cipher import AES

    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode('utf-8', 'ignore').strip()
    else:
        text = str(data).strip()
    for prefix in ('1ftunnel://1FTnl/', '1ftunnel://1FT1/', '1FTnl.', '1FT1.'):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    text = ''.join(text.split())
    raw = None
    if text:
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                raw = decoder(text + '=' * (-len(text) % 4))
                break
            except Exception:
                continue
    if raw is None:
        raw = bytes(data) if isinstance(data, (bytes, bytearray)) else b''
    if len(raw) < 40 + 16 or raw[0] != 3:
        raise ValueError('Invalid 1FTnl file')

    salt, nonce = raw[4:20], raw[20:32]
    aad_len = struct.unpack('>I', raw[32:36])[0]
    ct_len = struct.unpack('>I', raw[36:40])[0]
    if 40 + aad_len + 16 > len(raw):
        raise ValueError('Invalid 1FTnl file (bad header lengths)')
    aad = raw[40:40 + aad_len]
    ciphertext = raw[40 + aad_len:40 + aad_len + ct_len] if ct_len else raw[40 + aad_len:]
    if len(ciphertext) <= 16:
        raise ValueError('Invalid 1FTnl file (empty payload)')

    # AAD tail: blockRoot flag, lock mode (0=open, 1=app-locked, 2=password),
    # key version.
    lock_mode = aad[-2] if len(aad) >= 3 else 0
    if lock_mode == 2 and password is None:
        raise ValueError(
            'This 1FTnl file is password-protected: provide a password to decrypt it'
        )

    plaintext = None
    for key in _ftnl_derive_key(salt, aad, password):
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
            break
        except Exception:
            continue
    if plaintext is None:
        if password is not None:
            raise ValueError('Wrong password for this 1FTnl file')
        if lock_mode == 2:
            raise ValueError(
                'This 1FTnl file is password-protected: provide a password to decrypt it'
            )
        raise ValueError('Could not decrypt 1FTnl file (unsupported version or corrupt data)')

    cfg = _ftnl_parse_payload(plaintext)
    return _ftnl_flatten(cfg, None)


if __name__ == '__main__':
    sys.exit(main())
