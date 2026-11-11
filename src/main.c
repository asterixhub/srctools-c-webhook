/* srctools-c-webhook: minimal SRC Discord webhook worker (pitc only) */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <ctype.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

#define GAME_ID "o1y3oqv6"
#define GAME_NAME "Parkour in the city"
#define API_HOST "www.speedrun.com"
#define API_BASE "/api/v1"
#define RUN_EMBEDS "category,level,players"
#define RUN_PAGE 10
#define CHECK_INTERVAL 8
#define STATE_CAP 600

typedef struct { char *d; size_t n, c; } Buf;
typedef struct { char *s; size_t n; } Str;

static void die(const char *m){ fprintf(stderr,"%s\n",m); exit(1);} 
static void *xmalloc(size_t n){ void*p=malloc(n?n:1); if(!p) die("oom"); return p; }
static void *xrealloc(void*p,size_t n){ void*q=realloc(p,n?n:1); if(!q) die("oom"); return q; }
static char *xstrdup(const char*s){ size_t n=strlen(s); char*p=xmalloc(n+1); memcpy(p,s,n+1); return p; }
static void binit(Buf*b){ b->c=256; b->n=0; b->d=xmalloc(b->c); b->d[0]=0; }
static void badd(Buf*b,const void*s,size_t n){ if(b->n+n+1>b->c){ while(b->n+n+1>b->c) b->c*=2; b->d=xrealloc(b->d,b->c);} memcpy(b->d+b->n,s,n); b->n+=n; b->d[b->n]=0; }
static void bputs(Buf*b,const char*s){ badd(b,s,strlen(s)); }
static void bfmt(Buf*b,const char*fmt,...){ char tmp[1024]; va_list ap; va_start(ap,fmt); vsnprintf(tmp,sizeof tmp,fmt,ap); va_end(ap); bputs(b,tmp);} 
static void bfree(Buf*b){ free(b->d); b->d=NULL; b->n=b->c=0; }

static volatile sig_atomic_t stopflag=0;
static void on_sig(int s){ (void)s; stopflag=1; }

static long now_ms(void){ struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); return ts.tv_sec*1000L+ts.tv_nsec/1000000L; }
static void msleep(long ms){ if(ms<=0) return; struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(ms%1000)*1000000L; nanosleep(&ts,NULL); }

/* minimal JSON helpers: find string/number/object/array by key in flat object text is hard;
   instead use very targeted parsing for known SRC API shapes. */
static const char *skip_ws(const char*p){ while(p && (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')) p++; return p; }
static char *json_get_string(const char *obj, const char *key);
static char *json_get_raw(const char *obj, const char *key);

static const char *find_key(const char *obj,const char*key){
    if(!obj||!key) return NULL;
    size_t klen=strlen(key);
    const char*p=obj;
    int depth=0; bool in_str=false; bool esc=false;
    /* find key at current object level (depth 1 when inside { }) */
    if(*p=='{') { p++; depth=1; }
    while(*p){
        char c=*p;
        if(in_str){ if(esc) esc=false; else if(c=='\\') esc=true; else if(c=='"') in_str=false; p++; continue; }
        if(c=='"'){
            if(depth==1){
                const char*start=p+1;
                const char*q=start;
                while(*q && *q!='"'){ if(*q=='\\'&&q[1]) q+=2; else q++; }
                size_t len=q-start;
                if(len==klen && strncmp(start,key,klen)==0){
                    const char*r=skip_ws(q+1);
                    if(*r==':') return skip_ws(r+1);
                }
            }
            in_str=true; p++; continue;
        }
        if(c=='{'||c=='[') depth++;
        else if(c=='}'||c==']') { depth--; if(depth<=0) return NULL; }
        p++;
    }
    return NULL;
}

static char *unescape_json_str(const char*s,size_t len){
    Buf b; binit(&b);
    for(size_t i=0;i<len;i++){
        unsigned char c=(unsigned char)s[i];
        if(c=='\\' && i+1<len){
            char e=s[++i];
            if(e=='n') badd(&b,"\n",1); else if(e=='t') badd(&b,"\t",1); else if(e=='r') badd(&b,"\r",1);
            else if(e=='"') badd(&b,"\"",1); else if(e=='\\') badd(&b,"\\",1); else if(e=='/'){badd(&b,"/",1);} 
            else if(e=='u' && i+4<len){ unsigned v=0; for(int k=0;k<4;k++){ char h=s[i+1+k]; v<<=4; if(h>='0'&&h<='9') v|=h-'0'; else if(h>='a'&&h<='f') v|=10+h-'a'; else if(h>='A'&&h<='F') v|=10+h-'A'; } i+=4; char tmp[4]; int n=0; if(v<0x80){tmp[0]=v;n=1;} else if(v<0x800){tmp[0]=0xC0|(v>>6);tmp[1]=0x80|(v&0x3F);n=2;} else {tmp[0]=0xE0|(v>>12);tmp[1]=0x80|((v>>6)&0x3F);tmp[2]=0x80|(v&0x3F);n=3;} badd(&b,tmp,n); }
            else { badd(&b,&e,1);} 
        } else badd(&b,&c,1);
    }
    return b.d;
}

static char *json_get_string(const char *obj,const char*key){
    const char*v=find_key(obj,key); if(!v||*v!='"') return NULL;
    v++;
    const char*start=v;
    while(*v){ if(*v=='\\'&&v[1]) v+=2; else if(*v=='"') break; else v++; }
    if(*v!='"') return NULL;
    return unescape_json_str(start,(size_t)(v-start));
}

static char *json_get_raw(const char *obj,const char*key){
    const char*v=find_key(obj,key); if(!v) return NULL;
    const char*p=v; int depth=0; bool in_str=false; bool esc=false;
    while(*p){
        char c=*p;
        if(in_str){ if(esc) esc=false; else if(c=='\\') esc=true; else if(c=='"') in_str=false; p++; continue; }
        if(c=='"'){ in_str=true; p++; continue; }
        if(c=='{'||c=='[') depth++;
        else if(c=='}'||c==']'){ if(depth==0) break; depth--; }
        else if((c==','||c=='}'||c==']') && depth==0) break;
        p++;
    }
    size_t len=(size_t)(p-v); char*out=xmalloc(len+1); memcpy(out,v,len); out[len]=0; return out;
}

static double json_get_num(const char*obj,const char*key,double def){
    char*r=json_get_raw(obj,key); if(!r) return def; double d=strtod(r,NULL); free(r); return d; }

/* ---------------- config ---------------- */

static int interval_sec = CHECK_INTERVAL;
static const char *game_id = GAME_ID;
static bool use_new = true, use_verified = true, use_rejected = true;

static char *trim_dup(const char *s){ while(*s==' '||*s=='\t'||*s=='\r'||*s=='\n') s++; size_t n=strlen(s); while(n>0&&(s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\r'||s[n-1]=='\n')) n--; char*o=xmalloc(n+1); memcpy(o,s,n); o[n]=0; return o; }

/* ---------------- TLS client ---------------- */
typedef struct { mbedtls_net_context net; mbedtls_ssl_context ssl; mbedtls_ssl_config conf; mbedtls_ctr_drbg_context ctr; mbedtls_entropy_context ent; bool ok; } Tls;
static mbedtls_x509_crt g_cacrt;
static bool g_ca_ready = false;

static int tls_connect(Tls*t,const char*host,const char*port){
    mbedtls_net_init(&t->net); mbedtls_ssl_init(&t->ssl); mbedtls_ssl_config_init(&t->conf); mbedtls_ctr_drbg_init(&t->ctr); mbedtls_entropy_init(&t->ent); t->ok=false;
    if(mbedtls_ctr_drbg_seed(&t->ctr,mbedtls_entropy_func,&t->ent,(const unsigned char*)"s",1)!=0) return -1;
    if(mbedtls_net_connect(&t->net,host,port,MBEDTLS_NET_PROTO_TCP)!=0) return -1;
    if(mbedtls_ssl_config_defaults(&t->conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT)!=0) return -1;
    if(!g_ca_ready){ mbedtls_x509_crt_init(&g_cacrt); if(mbedtls_x509_crt_parse_file(&g_cacrt,"/etc/ssl/certs/ca-certificates.crt")==0) g_ca_ready=true; else mbedtls_x509_crt_free(&g_cacrt); }
    if(g_ca_ready){ mbedtls_ssl_conf_ca_chain(&t->conf,&g_cacrt,NULL); mbedtls_ssl_conf_authmode(&t->conf,MBEDTLS_SSL_VERIFY_REQUIRED); }
    else mbedtls_ssl_conf_authmode(&t->conf,MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&t->conf,mbedtls_ctr_drbg_random,&t->ctr);
    if(mbedtls_ssl_setup(&t->ssl,&t->conf)!=0) return -1;
    mbedtls_ssl_set_hostname(&t->ssl,host);
    mbedtls_ssl_set_bio(&t->ssl,&t->net,mbedtls_net_send,mbedtls_net_recv,NULL);
    int r; while((r=mbedtls_ssl_handshake(&t->ssl))!=0){ if(r!=MBEDTLS_ERR_SSL_WANT_READ&&r!=MBEDTLS_ERR_SSL_WANT_WRITE) return -1; }
    t->ok=true; return 0;
}
static int tls_write_all(Tls*t,const unsigned char*buf,size_t len){ while(len>0){ int r=mbedtls_ssl_write(&t->ssl,buf,len); if(r<=0) return -1; buf+=r; len-=r; } return 0; }
static char* tls_read_all(Tls*t,size_t*olen){ Buf b; binit(&b); unsigned char tmp[4096]; for(;;){ int r=mbedtls_ssl_read(&t->ssl,tmp,sizeof tmp); if(r==MBEDTLS_ERR_SSL_WANT_READ||r==MBEDTLS_ERR_SSL_WANT_WRITE) continue; if(r==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY||r==0) break; if(r<0) break; badd(&b,tmp,(size_t)r);} *olen=b.n; return b.d; }
static void tls_close(Tls*t){ if(t->ok){ mbedtls_ssl_close_notify(&t->ssl);} mbedtls_net_free(&t->net); mbedtls_ssl_free(&t->ssl); mbedtls_ssl_config_free(&t->conf); mbedtls_ctr_drbg_free(&t->ctr); mbedtls_entropy_free(&t->ent); }

static char *https_request(const char*host,const char*path,const char*method,const char*body,const char*extra_hdr,int*status){
    Tls t; if(tls_connect(&t,host,"443")!=0){ tls_close(&t); return NULL; }
    Buf req; binit(&req);
    bfmt(&req,"%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: s\r\nConnection: close\r\n",method,path,host);
    if(extra_hdr&&extra_hdr[0]) bputs(&req,extra_hdr);
    if(body){ bfmt(&req,"Content-Type: application/json\r\nContent-Length: %zu\r\n",strlen(body)); }
    bputs(&req,"\r\n");
    if(body) bputs(&req,body);
    if(tls_write_all(&t,(unsigned char*)req.d,req.n)!=0){ bfree(&req); tls_close(&t); return NULL; }
    bfree(&req);
    size_t rn=0; char*resp=tls_read_all(&t,&rn); tls_close(&t);
    if(!resp) return NULL;
    *status=0;
    char*sp=strstr(resp,"\r\n\r\n"); if(!sp){ free(resp); return NULL; }
    *sp=0; char*body_out=xstrdup(sp+4);
    if(sscanf(resp,"HTTP/%*d.%*d %d",status)!=1) *status=0;
    free(resp); return body_out;
}

/* Discord webhook host/path split */
static char wh_host[256]="discord.com"; static char wh_path[512]="";
static void parse_webhook(const char*url){
    const char*p=url; if(strncmp(p,"https://",8)==0) p+=8; else if(strncmp(p,"http://",7)==0) p+=7;
    const char*sl=strchr(p,'/'); if(!sl){ strncpy(wh_host,p,sizeof wh_host-1); wh_path[0]='/'; wh_path[1]=0; return; }
    size_t hl=(size_t)(sl-p); if(hl>=sizeof wh_host) hl=sizeof wh_host-1; memcpy(wh_host,p,hl); wh_host[hl]=0; strncpy(wh_path,sl,sizeof wh_path-1); wh_path[sizeof wh_path-1]=0;
}

/* state: simple persistence */
typedef struct { char id[32]; } Seen;
typedef struct { char feed[8]; bool primed; Seen seen[STATE_CAP]; int nseen; } FState;
static FState fst[3];
static char state_path[512];
static bool state_dirty=false;

static int fidx(const char*k){ if(strcmp(k,"new")==0) return 0; if(strcmp(k,"verified")==0) return 1; return 2; }
static void state_load_file(void){ for(int i=0;i<3;i++){ fst[i].primed=false; fst[i].nseen=0; }
    FILE*f=fopen(state_path,"r"); if(!f) return;
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    char*all=xmalloc((size_t)sz+2); size_t rd=fread(all,1,(size_t)sz,f); all[rd]=0; all[rd+1]=0; fclose(f);
    char*line=all;
    while(line&&*line){
        char*nl=strchr(line,'\n'); if(nl) *nl=0;
        char*k=strtok(line,"|"); char*pr=strtok(NULL,"|"); char*ids=strtok(NULL,"");
        if(k){ int i=fidx(k); if(i>=0&&i<3){ fst[i].primed=pr&&strcmp(pr,"1")==0; fst[i].nseen=0; if(ids){ char*tok=strtok(ids,","); while(tok&&fst[i].nseen<STATE_CAP){ while(*tok==' ') tok++; char*e=tok+strlen(tok); while(e>tok&&isspace((unsigned char)e[-1])) *--e=0; if(*tok){ strncpy(fst[i].seen[fst[i].nseen].id,tok,31); fst[i].seen[fst[i].nseen].id[31]=0; fst[i].nseen++; } tok=strtok(NULL,","); } } } }
        line=nl?nl+1:NULL;
    }
    free(all);
}
static void state_save_file(void){ if(!state_dirty) return; FILE*f=fopen(state_path,"w"); if(!f) return; const char*names[3]={"new","verified","rejected"}; for(int i=0;i<3;i++){ fprintf(f,"%s|%d|",names[i],fst[i].primed?1:0); for(int j=0;j<fst[i].nseen;j++){ if(j) fputc(',',f); fprintf(f,"%s",fst[i].seen[j].id);} fputc('\n',f);} fclose(f); state_dirty=false; }
static bool seen_has(int fi,const char*id){ for(int j=0;j<fst[fi].nseen;j++) if(strcmp(fst[fi].seen[j].id,id)==0) return true; return false; }
static void seen_add(int fi,const char*id){ if(seen_has(fi,id)) return; if(fst[fi].nseen<STATE_CAP){ strncpy(fst[fi].seen[fst[fi].nseen].id,id,31); fst[fi].seen[fst[fi].nseen].id[31]=0; fst[fi].nseen++; }
    else { memmove(&fst[fi].seen[0],&fst[fi].seen[1],sizeof(Seen)*(STATE_CAP-1)); strncpy(fst[fi].seen[STATE_CAP-1].id,id,31); fst[fi].seen[STATE_CAP-1].id[31]=0; } state_dirty=true; }

/* helpers */
static void json_escape(Buf*b,const char*s){ badd(b,"\"",1); if(!s) s=""; for(const unsigned char*p=(const unsigned char*)s;*p;p++){ if(*p=='"'||*p=='\\'){ char t[2]={'\\',(char)*p}; badd(b,t,2);} else if(*p=='\n') bputs(b,"\\n"); else if(*p=='\r') bputs(b,"\\r"); else if(*p=='\t') bputs(b,"\\t"); else if(*p<0x20){ char t[7]; snprintf(t,sizeof t,"\\u%04x",*p); bputs(b,t);} else badd(b,p,1);} badd(b,"\"",1); }
static char *clean(const char*s,int max){ if(!s) return xstrdup(""); Buf b; binit(&b); for(const unsigned char*p=(const unsigned char*)s;*p;p++){ if(*p=='\n'||*p=='\r'||*p=='\t') badd(&b," ",1); else if(*p>=0x20) badd(&b,p,1);} /* trim */ char*d=b.d; while(*d==' ') d++; char*end=d+strlen(d); while(end>d&&end[-1]==' ') *--end=0; char*o=xstrdup(d); bfree(&b); if((int)strlen(o)>max) o[max]=0; return o; }
static void fmt_compact(Buf*b,double sec){ long long ms=(long long)(sec*1000.0+0.5); long long m=ms/60000; long long s=(ms/1000)%60; long long ml=ms%1000; bfmt(b,"%lldm %llds %03lldms",m,s,ml); }

/* send discord */
static const char* ev_title(const char*k){ if(strcmp(k,"new")==0) return "\xF0\x9F\x8F\x86 New Run"; if(strcmp(k,"verified")==0) return "\xE2\x9C\x85 Run verified"; return "\xE2\x9D\x8C Run rejected"; }
static long ev_color(const char*k){ if(strcmp(k,"new")==0) return 0x5865f2; if(strcmp(k,"verified")==0) return 0x57f287; return 0xed4245; }

static bool send_discord(const char*kind,const char*run_url,const char*map,const char*time_s,const char*runner,const char*reason){
    Buf pl; binit(&pl);
    bputs(&pl,"{\"embeds\":[{\"title\":"); json_escape(&pl,ev_title(kind));
    bputs(&pl,",\"url\":"); json_escape(&pl,run_url?run_url:"");
    char desc[1200]; if(reason&&reason[0]) snprintf(desc,sizeof desc,"%s in %s by %s\nReason: %s",map,time_s,runner,reason); else snprintf(desc,sizeof desc,"%s in %s by %s",map,time_s,runner);
    bputs(&pl,",\"description\":"); json_escape(&pl,desc);
    bfmt(&pl,",\"color\":%ld}],\"allowed_mentions\":{\"parse\":[]}}",ev_color(kind));
    bool ok=false;
    for(int attempt=1;attempt<=3;attempt++){
        int st=0; char*resp=https_request(wh_host,wh_path,"POST",pl.d,NULL,&st); if(resp) free(resp);
        if(st==204||st==200){ ok=true; break; }
        if(st==429){ msleep(1500); continue; }
        if(st>=500){ msleep(1000*attempt); continue; }
        break;
    }
    bfree(&pl);
    return ok;
}

/* extract runs and notify */
static char* json_embedded_string(const char*obj,const char*key){
    if(!obj) return NULL;
    const char*d=find_key(obj,"data");
    if(d&&*d=='{') return json_get_string(d,key);
    return NULL;
}

static char* player_name_from_obj(const char*obj){
    char*names=json_get_raw(obj,"names");
    if(names && names[0]=='{'){ char*n=json_get_string(names,"international"); if(!n) n=json_get_string(names,"japanese"); if(n){ free(names); return n; } }
    if(names) free(names);
    char*n=json_get_string(obj,"name"); if(n) return n; return xstrdup("Unknown runner");
}

static void process_feed(const char*status,const char*kind){
    char path[512]; const char*orderby=strcmp(status,"verified")==0?"verify-date":"submitted";
    snprintf(path,sizeof path,"%s/runs?game=%s&status=%s&orderby=%s&direction=desc&embed=%s&max=%d&_=%lld",API_BASE,game_id,status,orderby,RUN_EMBEDS,RUN_PAGE,(long long)now_ms());
    char hdr[256]; const char*key=getenv("SPEEDRUN_API_KEY"); if(key&&key[0]) snprintf(hdr,sizeof hdr,"Accept: application/json\r\nX-API-Key: %s\r\n",key); else snprintf(hdr,sizeof hdr,"Accept: application/json\r\n");
    int st=0; char*body=https_request(API_HOST,path,"GET",NULL,hdr,&st);
    if(!body||st<200||st>=300){ if(body) free(body); return; }
    const char*data=find_key(body,"data");
    if(!data||*data!='['){ free(body); return; }

    int fi=fidx(kind);
    /* collect run ids in order (parsed in place, no copy of the whole feed) */
    char ids[RUN_PAGE+2][32]; int nids=0; const char*objs[RUN_PAGE+2];
    const char*p=data+1;
    while(*p && nids<RUN_PAGE){
        p=skip_ws(p); if(*p==']') break; if(*p!='{'){ p++; continue; }
        const char*start=p; int depth=0; bool in_str=false,esc=false;
        do{ char c=*p; if(in_str){ if(esc) esc=false; else if(c=='\\') esc=true; else if(c=='"') in_str=false; } else { if(c=='"') in_str=true; else if(c=='{') depth++; else if(c=='}') depth--; } p++; }while(*p && depth>0);
        bool got=false;
        { const char*idp=find_key(start,"id"); if(idp&&*idp=='"'){ const char*q=idp+1; size_t n=0; while(*q&&*q!='"'&&n<31){ ids[nids][n++]=*q++; } ids[nids][n]=0; got=true; } }
        if(got){ objs[nids]=start; nids++; }
        p=skip_ws(p); if(*p==',') p++;
    }

    /* determine notifications */
    char notify[RUN_PAGE+2][32]; int nn=0;
    bool was_primed=fst[fi].primed;
    if(!was_primed){ fst[fi].primed=true; state_dirty=true; }
    else {
        for(int i=nids-1;i>=0;i--){ if(!seen_has(fi,ids[i])){ strncpy(notify[nn],ids[i],31); notify[nn][31]=0; nn++; } }
    }
    printf("[Worker] feed %s: %d run(s), primed=%d, notify=%d\n",kind,nids,(int)was_primed,nn); fflush(stdout);
    /* update seen and highwater */
    for(int i=0;i<nids;i++){ seen_add(fi,ids[i]); }
    state_save_file();
    /* send notifications */
    for(int k=0;k<nn;k++){
        /* find object */
        const char*obj=NULL; for(int i=0;i<nids;i++) if(strcmp(ids[i],notify[k])==0){ obj=objs[i]; break; }
        if(!obj) continue;
        char*run_url=json_get_string(obj,"weblink"); if(!run_url){ run_url=xmalloc(96); snprintf(run_url,96,"https://www.speedrun.com/pitc/runs/%s",notify[k]); }
        char*cat_raw=json_get_raw(obj,"category"); char*lvl_raw=json_get_raw(obj,"level"); char*players_raw=json_get_raw(obj,"players");
        char*mapn=NULL; if(lvl_raw) mapn=json_embedded_string(lvl_raw,"name"); if(mapn&&!mapn[0]){ free(mapn); mapn=NULL; } if(!mapn && cat_raw) mapn=json_embedded_string(cat_raw,"name"); if(mapn&&!mapn[0]){ free(mapn); mapn=NULL; } if(!mapn) mapn=xstrdup("Unknown map");
        char*runner=xstrdup("Unknown runner");
        if(players_raw&&players_raw[0]=='{'){ char*d=json_get_raw(players_raw,"data"); if(d&&d[0]=='['){ /* first element */ const char*q=skip_ws(d+1); if(*q=='{'){ int dp=0; bool ins=false,es=false; const char*st=q; do{ char c=*q; if(ins){if(es)es=false;else if(c=='\\')es=true;else if(c=='"')ins=false;} else {if(c=='"')ins=true; else if(c=='{')dp++; else if(c=='}')dp--; } q++; }while(*q && dp>0); size_t l=(size_t)(q-st); char*po=xmalloc(l+1); memcpy(po,st,l); po[l]=0; free(runner); runner=player_name_from_obj(po); free(po);} } if(d) free(d);} 
        char*t_raw=json_get_raw(obj,"times"); double psec=0; if(t_raw&&t_raw[0]=='{') psec=json_get_num(t_raw,"primary_t",0); if(t_raw) free(t_raw);
        Buf tb; binit(&tb); if(psec>0) fmt_compact(&tb,psec); else bputs(&tb,"?"); char*time_s=xstrdup(tb.d); bfree(&tb);
        char*reason=NULL; if(strcmp(kind,"rejected")==0){ char*straw=json_get_raw(obj,"status"); if(straw&&straw[0]=='{') reason=json_get_string(straw,"reason"); if(straw) free(straw); }
        char*mapc=clean(mapn,256); char*runc=clean(runner,256); char*reas_c=reason?clean(reason,300):NULL;
        printf("[Worker] %s %s\n",kind,notify[k]); fflush(stdout);
        send_discord(kind,run_url,mapc,time_s,runc,reas_c?reas_c:"");
        free(mapc); free(runc); if(reas_c) free(reas_c); if(reason) free(reason); free(time_s); free(runner); free(mapn); if(players_raw) free(players_raw); if(lvl_raw) free(lvl_raw); if(cat_raw) free(cat_raw); free(run_url);
        msleep(800);
    }

    free(body);
    state_save_file();
}

int main(void){
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);
    setvbuf(stdout,NULL,_IOLBF,0);
    const char*iv=getenv("CHECK_INTERVAL_SECONDS"); if(iv&&*iv){ int v=atoi(iv); if(v>=1&&v<=3600) interval_sec=v; }
    const char*gv=getenv("MONITORED_GAME_IDS"); if(gv&&*gv){ char*tmp=xstrdup(gv); char*comma=strchr(tmp,','); if(comma) *comma=0; char*t=trim_dup(tmp); if(t[0]) game_id=t; free(tmp); }
    { const char*ev=getenv("MONITORED_EVENTS"); if(ev&&*ev){ use_new=use_verified=use_rejected=false; char*tmp=xstrdup(ev); char*save=NULL; char*tok=strtok_r(tmp,",",&save); while(tok){ char low[64]; snprintf(low,sizeof low,"%s",tok); for(char*q=low;*q;q++) if(*q>='A'&&*q<='Z') *q=(char)(*q-'A'+'a'); if(!strcmp(low,"new")||!strcmp(low,"newrun")) use_new=true; else if(!strcmp(low,"verified")||!strcmp(low,"approved")) use_verified=true; else if(!strcmp(low,"rejected")) use_rejected=true; tok=strtok_r(NULL,",",&save); } free(tmp); } }
    const char*wh=getenv("DISCORD_WEBHOOK_URL");
    if(!wh||!wh[0]){ printf("[Config] DISCORD_WEBHOOK_URL is required\n"); fflush(stdout); return 1; }
    parse_webhook(wh);
    const char*vol=getenv("RAILWAY_VOLUME_MOUNT_PATH"); if(!vol||!*vol) vol="./data";
    mkdir(vol,0755);
    snprintf(state_path,sizeof state_path,"%s/state.txt",vol);
    const char*reset=getenv("RESET_STATE");
    if(!(reset&&strcmp(reset,"1")==0)) state_load_file();
    printf("[Worker] Started; polling every %ds (game=%s %s)\n",interval_sec,game_id,GAME_NAME); fflush(stdout);
    const char*test=getenv("TEST_NOTIFY");
    if(test&&strcmp(test,"1")==0){ bool ok=send_discord("new","https://www.speedrun.com/pitc","Parkour in the city","0m 12s 345ms","Test runner",""); printf("[Worker] Test notification: %s\n",ok?"sent":"failed"); fflush(stdout); }
    while(!stopflag){
        long t0=now_ms();
        if(use_new) process_feed("new","new");
        if(stopflag) break;
        if(use_verified) process_feed("verified","verified");
        if(stopflag) break;
        if(use_rejected) process_feed("rejected","rejected");
        long dt=now_ms()-t0; long wait=interval_sec*1000L-dt; if(wait<500) wait=500;
        long end=now_ms()+wait; while(!stopflag && now_ms()<end) msleep(250);
    }
    state_save_file();
    printf("[Worker] Stopped\n"); fflush(stdout);
    return 0;
}