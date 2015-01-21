# $FreeBSD$

PORTNAME=	mlvpn
PORTVERSION=	2.0.2
PORTREVISION=	1
CATEGORIES=	net
MASTER_SITES=	GH
DISTNAME=	${GH_ACCOUNT}-${GH_PROJECT}-${GH_COMMIT}

MAINTAINER=	ed@zehome.com
COMMENT=	Multi-link VPN (network aggregator)

LICENSE=	BSD3CLAUSE

LIB_DEPENDS=	libev.so:${PORTSDIR}/devel/libev \
		libsodium.so:${PORTSDIR}/security/libsodium

GNU_CONFIGURE=	yes
USES=		autoreconf
CPPFLAGS+=	-I${LOCALBASE}/include
LDFLAGS+=	-L${LOCALBASE}/lib
MAKE_JOBS_UNSAFE=yes

USE_GITHUB=	yes
GH_ACCOUNT=	zehome
GH_PROJECT=	MLVPN
GH_COMMIT=	6589112
GH_TAGNAME=	${PORTVERSION}

USERS=		mlvpn
UID=		401

USE_RC_SUBR=	mlvpn
SUB_FILES=	pkg-message

OPTIONS_DEFINE=	CONTROL
CONTROL_DESC=	Enable UNIX socket/HTTP json remote control API

OPTIONS_DEFAULT=CONTROL

.include <bsd.port.options.mk>

.if ! ${PORT_OPTIONS:MCONTROL}
CONFIGURE_ARGS+=--disable-control
.endif

.include <bsd.port.mk>
