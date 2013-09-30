#include "ev_sock.c"
#include <errno.h>

#define CHECK_NOT_CONN() STMT_START{ \
		if (unlikely(!self->self)) return ;\
		if (unlikely(self->cnn.state != CONNECTED)) { \
			if (!self->postpone) self->postpone = newAV(); \
			AV *pp = newAV(); \
			av_push(self->postpone,newRV_noinc((SV *)pp)); \
			SvREFCNT_inc(cb); \
			av_push(pp,cb); \
			av_push(pp,&PL_sv_undef); \
			av_push(pp,newSVpv( "Not connected",0 )); \
			ev_timer_start(self->cnn.loop, &self->postpone_timer); \
			XSRETURN_UNDEF; \
			return; \
		} \
} STMT_END

#define EVSockCheckConn(self) STMT_START{ \
		if (unlikely(!self->self)) return ;\
		if (unlikely(self->cnn.state != CONNECTED)) { \
			if (!self->postpone) self->postpone = newAV(); \
			AV *pp = newAV(); \
			av_push(self->postpone,newRV_noinc((SV *)pp)); \
			SvREFCNT_inc(cb); \
			av_push(pp,cb); \
			av_push(pp,&PL_sv_undef); \
			av_push(pp,newSVpv( "Not connected",0 )); \
			ev_timer_start(self->cnn.loop, &self->postpone_timer); \
			XSRETURN_UNDEF; \
			return; \
		} \
} STMT_END


#define EVSockStruct(Type) \
	Cnn cnn; \
	struct iovec iov; \
	SV *self; \
	SV *wbuf; \
	SV *rbuf; \
	SV *connected; \
	SV *disconnected; \
	SV *connfail; \
	ev_timer postpone_timer; \
	AV *postpone;\
	HV *stash; \
	\
	void (*on_disconnect_before)(struct Type * self, int error); \
	void (*on_disconnect_after)(struct Type * self, int error); \
	void (*on_connect_before)(struct Type * self, struct sockaddr_in *peer); \
	void (*on_connect_after)(struct Type * self, struct sockaddr_in *peer)

struct _EVSockDefault;
struct _EVSockDefault {
	EVSockStruct(_EVSockDefault);
};
typedef struct _EVSockDefault EVSockDefault;

static inline int sv_inet_aton(SV * sv_addr) {
	struct in_addr ip;
	inet_aton(SvPV_nolen(sv_addr), &ip);
	return ip.s_addr;
}



#define EVSockNew(Type, on_read_handler) \
	if (items < 2 || !SvROK(ST(1)) || SvTYPE(SvRV(ST(1))) != SVt_PVHV) croak("Usage: %s->new({ options })",SvPV_nolen(ST(0)));\
	Type * self = (Type *) safemalloc( sizeof(Type) ); \
	memset(self,0,sizeof(Type)); \
	self->stash = gv_stashpv(SvPV_nolen(ST(0)), TRUE); \
	{ SV *iv = newSViv(PTR2IV( self )); \
	self->self = sv_bless(newRV_noinc (iv), self->stash); \
	ST(0) = sv_2mortal(sv_bless (newRV_noinc(iv), self->stash)); } \
	self->cnn.loop = EV_DEFAULT; \
	HV *args = (HV*) SvRV(ST(1));\
	Cnn *cnn = &self->cnn;\
	{\
		int read_buffer = 0x20000;\
		SV **key;\
		if ((key = hv_fetchs(args, "timeout", 0)) ) cnn->connect_timeout = cnn->rw_timeout = SvNV(*key); \
		if ((key = hv_fetchs(args, "read_buffer", 0)) && SvOK(*key) && SvUV(*key) > 0 ) read_buffer = SvUV(*key); \
		if ((key = hv_fetchs(conf, "reconnect", 0)) ) { \
			cnn->reconnect = SvNV(*key); \
		} \
		else { \
			cnn->reconnect = 1./3; \
		} \
		\
		self->rbuf = newSV( read_buffer ); \
		SvUPGRADE( self->rbuf, SVt_PV ); \
		cnn->rbuf = SvPVX(self->rbuf); \
		cnn->rlen = SvLEN(self->rbuf); \
		\
		cnn->iov = &self->iov;\
		cnn->iovcnt = 1;\
		\
		if ((key = hv_fetchs(conf, "connected", 0)) && SvROK(*key)) SvREFCNT_inc(self->connected = *key);\
		if ((key = hv_fetchs(conf, "disconnected", 0)) && SvROK(*key)) SvREFCNT_inc(self->disconnected = *key);\
		if ((key = hv_fetchs(conf, "connfail", 0)) && SvROK(*key)) SvREFCNT_inc(self->connfail = *key);\
		cnn->on_connected = (c_cb_conn_t)on_connected;\
		cnn->on_disconnect = (c_cb_err_t)on_disconnect;\
		cnn->on_connfail = (c_cb_err_t)on_connfail;\
		cnn->on_read = (c_cb_read_t)on_read_handler;\
		\
		/* todo: resolving */ \
		if ((key = hv_fetch(conf, "host", 4, 0)) && SvOK(*key)) {\
			self->cnn.iaddr.sin_addr.s_addr = sv_inet_aton( *key );\
		}\
		else { croak("host required"); } \
		if ((key = hv_fetch(conf, "port", 4, 0)) && SvOK(*key)) { \
			self->cnn.iaddr.sin_port = htons( SvUV( *key ) ); \
		} \
		else { croak("port required"); } \
		self->cnn.iaddr.sin_family      = AF_INET; \
		\
		self->postpone = 0;\
		ev_timer_init(&self->postpone_timer,postpone_cb,0,0);\
		\
		do_check(cnn);\
		\
	} \

#define EVSockSelf(type) register type *self = ( type * ) SvUV( SvRV( ST(0) ) )

#define EVSockDestroy(self) \
	if (self->connected) SvREFCNT_dec(self->connected); \
	if (self->connfail) SvREFCNT_dec(self->connfail); \
	if (self->disconnected) SvREFCNT_dec(self->disconnected); \
	if (self->rbuf) SvREFCNT_dec(self->rbuf); \
	if (self->wbuf) SvREFCNT_dec(self->wbuf); \
	if (self->self && SvOK(self->self) && SvOK( SvRV(self->self) )) { \
		SvREFCNT_inc(SvRV(self->self)); \
		SvREFCNT_dec(self->self); \
	} \
	\
	if (self->postpone) {\
		postpone_cb ( self->cnn.loop, &self->postpone_timer, 0);\
	}\
	\
	do_destroy(&self->cnn);\
	safefree(self);

XS(XS_EV_Sock_connect);
XS(XS_EV_Sock_connect)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;
	
	EVSockSelf(EVSockDefault);
	do_connect(&self->cnn);
	XSRETURN_UNDEF;
	PUTBACK;
	return;
}

XS(XS_EV_Sock_disconnect);
XS(XS_EV_Sock_disconnect)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;
	
	EVSockSelf(EVSockDefault);
	do_disconnect(&self->cnn);
	XSRETURN_UNDEF;
	PUTBACK;
	return;
}

XS(XS_EV_Sock_reconnect);
XS(XS_EV_Sock_reconnect)
{
	dVAR;dXSARGS;
	if (items != 1) croak_xs_usage(cv,  "self");
	PERL_UNUSED_VAR(ax);
	SP -= items;
	
	EVSockSelf(EVSockDefault);
	do_disconnect(&self->cnn);
	do_connect(&self->cnn);
	XSRETURN_UNDEF;
	PUTBACK;
	return;
}


#define I_EV_SOCK_API(Module) STMT_START {\
	char * file = __FILE__;\
	warn("boot: %s", Module "::connect");\
	newXS(Module "::connect", XS_EV_Sock_connect, file);\
	newXS(Module "::disconnect", XS_EV_Sock_disconnect, file);\
	newXS(Module "::reconnect", XS_EV_Sock_reconnect, file);\
} STMT_END

#define EVSockOnDisconnect(self, before, after) STMT_START {\
	if (before) self->on_disconnect_before = before;\
	if (after) self->on_disconnect_after = after;\
} STMT_END

void on_disconnect(Cnn *self, int error) {
	EVSockDefault * obj = (EVSockDefault *) self;
	dSP;
	if (obj->on_disconnect_before)
		obj->on_disconnect_before( (void *) self, error );
	
	/*
	ENTER;
	SAVETMPS;
	SV **sp1 = PL_stack_sp;
	*/
	if (obj->disconnected) {
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, 2);
			PUSHs( obj->self );
			PUSHs( sv_2mortal( newSVpv( strerror(error),0 ) ) );
		PUTBACK;
		errno = error;
		call_sv( obj->disconnected, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}
	
	/*
	PL_stack_sp = sp1;
	FREETMPS;
	LEAVE;
	*/
	if (obj->on_disconnect_after)
		obj->on_disconnect_after( (void *) self, error );
}

#define EVSockOnConnect(self, before, after) STMT_START {\
	if (before) self->on_connect_before = before;\
	if (after) self->on_connect_after = after;\
} STMT_END

void on_connected(Cnn *self, struct sockaddr_in *peer) {
	EVSockDefault * obj = (EVSockDefault *) self;
	dSP;
	if (obj->on_connect_before)
		obj->on_connect_before( (void *) self, peer );
	
	/*
	ENTER;
	SAVETMPS;
	SV **sp1 = PL_stack_sp;
	*/
	if (obj->connected) {
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, 3);
			PUSHs( obj->self );
			PUSHs( sv_2mortal( newSVpv( inet_ntoa( peer->sin_addr ),0 ) ) );
			PUSHs( sv_2mortal( newSVuv( ntohs( peer->sin_port ) ) ) );
		PUTBACK;
		call_sv( obj->connected, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}
	
	/*
	PL_stack_sp = sp1;
	FREETMPS;
	LEAVE;
	*/
	if (obj->on_connect_after)
		obj->on_connect_after( (void *) self, peer );
}

void on_connfail(Cnn *self, int err) {
	EVSockDefault * obj = (EVSockDefault *) self;
	dSP;
	if (obj->connfail) {
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, 2);
			PUSHs( obj->self );
			PUSHs( sv_2mortal( newSVpvf( "%s",strerror(err) ) ) );
		PUTBACK;
		errno = err;
		call_sv( obj->connfail, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}
}

void postpone_cb ( struct ev_loop *loop,  ev_timer *w, int revents) {
	EVSockDefault * self = (EVSockDefault *) ( (char*) w - (ptrdiff_t) &( (EVSockDefault *)0 )->postpone_timer );
	ev_timer_stop( loop, w );
	dSP;
	
	ENTER;
	SAVETMPS;
	SV **sp1 = PL_stack_sp;
	
	SV *cb;
	int i;
	AV *postpone = (AV *) sv_2mortal((SV *)self->postpone);
	
	self->postpone = 0;
	
	while (av_len( postpone ) > -1) {
		AV *pp = (AV *) SvRV(sv_2mortal(av_shift( postpone )));
		SV *cb = sv_2mortal(av_shift(pp));
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		EXTEND(SP, av_len(pp)+1);
		while (av_len(pp) > -1) {
			XPUSHs( sv_2mortal(av_shift(pp)) );
		}
		PUTBACK;
		call_sv( cb, G_DISCARD | G_VOID );
		FREETMPS;
		LEAVE;
	}
	
	PL_stack_sp = sp1;
	
	FREETMPS;
	LEAVE;
}
