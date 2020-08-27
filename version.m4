dnl define the OpenVPN version
define([PRODUCT_NAME], [OpenVPN])
define([PRODUCT_TARNAME], [openvpn])
define([PRODUCT_VERSION_MAJOR], [2])
define([PRODUCT_VERSION_MINOR], [5])
define([PRODUCT_VERSION_PATCH], [-20200904])
m4_append([PRODUCT_VERSION], [PRODUCT_VERSION_MAJOR])
m4_append([PRODUCT_VERSION], [PRODUCT_VERSION_MINOR], [[.]])
m4_append([PRODUCT_VERSION], [PRODUCT_VERSION_PATCH], [[]])
define([PRODUCT_BUGREPORT], [openvpn-users@lists.sourceforge.net])
define([PRODUCT_VERSION_RESOURCE], [2,5,0,4])
dnl define the TAP version
define([PRODUCT_TAP_WIN_COMPONENT_ID], [tap0901])
define([PRODUCT_TAP_WIN_MIN_MAJOR], [9])
define([PRODUCT_TAP_WIN_MIN_MINOR], [9])
