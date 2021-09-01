# Chapter 1 Load Engine

标准的Engine加载流程是不需要修改Engine原生代码的，称之为no-hack集成方式。

```c
  4 #include <dlfcn.h>
  5 #include <sslhw.h>
 
 
 10 #define SSLHW_ENGINE_SO "/lib/libqat.so"
 11 #define SSLHW_ENGINE_ID_QAT "qatengine"
 
 28 ENGINE*
 29 sslhw_load_dynamic_engine(const char *libpath, const char *libid)
 30 {   
 31     ENGINE *e = NULL;
 32     BIO *bio_err; 
 33     unsigned long errorno;
 34     
 35     if ((bio_err = BIO_new(BIO_s_file())) != NULL) {
 36         BIO_set_fp(bio_err, stderr, BIO_NOCLOSE|BIO_FP_TEXT);
 37     }
 38 
 39     e = ENGINE_by_id("dynamic");
 40     if (e == NULL) {
 41         goto err;
 42     }
 43     
 44     if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", libpath, 0)) {
 45         printf("set engine path failed\n");
 46         goto err;
 47     }
 48     
 49     if (!ENGINE_ctrl_cmd_string(e, "ID", libid, 0)) {
 50         printf("set engine name failed\n");
 51         goto err;
 52     }
 53     
 54     if (!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
 55         printf("load engine failed\n");
 56         goto err;
 57     }
 58 
 59     //printf("engine \"%s\" set.\n", ENGINE_get_id(e));
 60     return e;
 61 
 62 err:
 63 
 64     ERR_print_errors(bio_err);
 65     errorno = ERR_peek_error();
 66     printf("SSL load engine failed: %d(%s), func %s\n",ERR_GET_REASON(errorno),
 67             ERR_reason_error_string(errorno), ERR_func_error_string(errorno));
 68     
 69     if (e) {
 70         ENGINE_free(e);
 71         e = NULL;
 72     }
 73 
 74     return NULL;
 75 }
 76 
 77 static int
 78 sslhw_engine_ctrl_cmd(const char *cmd, long i, void *p, void(*f)(void),
 79                         int cmd_optional)
 80 {
 81     if (dynamic_engine == NULL) {
 82         return 0;
 83     }
 84 
 85     return ENGINE_ctrl_cmd(dynamic_engine, cmd, i, p, f, cmd_optional);
 86 }
 87
 88 int sslhw_load_engine(int all)
 89 {
 90     void *dlhan = NULL;
 92 
 93     dynamic_engine = sslhw_load_dynamic_engine(SSLHW_ENGINE_SO, SSLHW_ENGINE_ID_QAT);
 94     if (dynamic_engine == NULL) {
 95         return 0;
 96     }
 97 
 98     if (sslhw_qat_get_mode() != HW_MODE_POLLING) {
 99         sslhw_engine_ctrl_cmd("ENABLE_EVENT_DRIVEN_POLLING_MODE", 0, NULL, NULL, 0);
100     }
101 
102     sslhw_engine_ctrl_cmd("ENABLE_EXTERNAL_POLLING", 0, NULL, NULL, 0);
103     ENGINE_add(dynamic_engine);
104     ENGINE_init(dynamic_engine);
105     if (!ENGINE_set_default(dynamic_engine, ENGINE_METHOD_ALL)) {
106         goto err;
107     }
108 
109     if (!all) {
110         SSL_disable_combine_cipher();
111     }
128 
129     return 1;
130 
131 err:
132     if (dlhan) {
133         dlclose(dlhan);
134     }
135 
136     if (dynamic_engine != NULL) {
137         ENGINE_free(dynamic_engine);
138         dynamic_engine = NULL;
139     }
140 
141     return 0;
142 }
```

ENGINE\_by\_id\("dynamic"\)是以动态方式加载Engine:

```c
277 ENGINE *ENGINE_by_id(const char *id)
278 {
279     ENGINE *iterator;     
280     char *load_dir = NULL;
281     if (id == NULL) {     
282         ENGINEerr(ENGINE_F_ENGINE_BY_ID, ERR_R_PASSED_NULL_PARAMETER);
283         return NULL;      
284     }
285     if (!RUN_ONCE(&engine_lock_init, do_engine_lock_init)) {
286         ENGINEerr(ENGINE_F_ENGINE_BY_ID, ERR_R_MALLOC_FAILURE);
287         return NULL;      
288     }
289 
290     CRYPTO_THREAD_write_lock(global_engine_lock);
291     iterator = engine_list_head;   
292     while (iterator && (strcmp(id, iterator->id) != 0))
293         iterator = iterator->next;     
294     if (iterator != NULL) {
295         /*
296          * We need to return a structural reference. If this is an ENGINE
297          * type that returns copies, make a duplicate - otherwise increment
298          * the existing ENGINE's reference count.
299          */
300         if (iterator->flags & ENGINE_FLAGS_BY_ID_COPY) {
301             ENGINE *cp = ENGINE_new();     
302             if (cp == NULL)
303                 iterator = NULL;               
304             else {
305                 engine_cpy(cp, iterator);      
306                 iterator = cp;
307             }
308         } else {
309             iterator->struct_ref++;        
310             engine_ref_debug(iterator, 0, 1);
311         }
312     }
313     CRYPTO_THREAD_unlock(global_engine_lock);
314     if (iterator != NULL)
315         return iterator;
316     /*
317      * Prevent infinite recursion if we're looking for the dynamic engine.
318      */
319     if (strcmp(id, "dynamic")) {
320         if ((load_dir = ossl_safe_getenv("OPENSSL_ENGINES")) == NULL)
321             load_dir = ENGINESDIR;
322         iterator = ENGINE_by_id("dynamic");
323         if (!iterator || !ENGINE_ctrl_cmd_string(iterator, "ID", id, 0) ||
324             !ENGINE_ctrl_cmd_string(iterator, "DIR_LOAD", "2", 0) ||
325             !ENGINE_ctrl_cmd_string(iterator, "DIR_ADD",
326                                     load_dir, 0) ||
327             !ENGINE_ctrl_cmd_string(iterator, "LIST_ADD", "1", 0) ||
328             !ENGINE_ctrl_cmd_string(iterator, "LOAD", NULL, 0))
329             goto notfound;
330         return iterator;
331     }
332  notfound:
333     ENGINE_free(iterator);
334     ENGINEerr(ENGINE_F_ENGINE_BY_ID, ENGINE_R_NO_SUCH_ENGINE);
335     ERR_add_error_data(2, "id=", id);
336     return NULL;
337     /* EEK! Experimental code ends */
338 }
```

290-313: 遍历engine队列，查找id相同的engine; 

结果是一定能找到的，因为在OpenSSL初始化的时候就已经吧dynamic engine加入到队列中了：

```c
620 int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
621 {
...
726     if ((opts & OPENSSL_INIT_ENGINE_DYNAMIC)
727             && !RUN_ONCE(&engine_dynamic, ossl_init_engine_dynamic))
728         return 0;
...
```

```c
357 static CRYPTO_ONCE engine_dynamic = CRYPTO_ONCE_STATIC_INIT;
358 DEFINE_RUN_ONCE_STATIC(ossl_init_engine_dynamic)
359 {
360 # ifdef OPENSSL_INIT_DEBUG
361     fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_dynamic: "
362                     "engine_load_dynamic_int()\n");
363 # endif
364     engine_load_dynamic_int();
365     return 1;
366 }
```

```c
39 static const char *engine_dynamic_id = "dynamic";
...
234 static ENGINE *engine_dynamic(void)
235 {
236     ENGINE *ret = ENGINE_new();
237     if (ret == NULL)
238         return NULL;
239     if (!ENGINE_set_id(ret, engine_dynamic_id) ||
240         !ENGINE_set_name(ret, engine_dynamic_name) ||
241         !ENGINE_set_init_function(ret, dynamic_init) ||
242         !ENGINE_set_finish_function(ret, dynamic_finish) ||
243         !ENGINE_set_ctrl_function(ret, dynamic_ctrl) ||
244         !ENGINE_set_flags(ret, ENGINE_FLAGS_BY_ID_COPY) ||
245         !ENGINE_set_cmd_defns(ret, dynamic_cmd_defns)) {
246         ENGINE_free(ret);
247         return NULL;
248     }
249     return ret;
250 }
251
252 void engine_load_dynamic_int(void)
253 {
254     ENGINE *toadd = engine_dynamic();
255     if (!toadd)
256         return;
257     ENGINE_add(toadd);
258     /*
259      * If the "add" worked, it gets a structural reference. So either way, we
260      * release our just-created reference.
261      */
262     ENGINE_free(toadd);
263     /*
264      * If the "add" didn't work, it was probably a conflict because it was
265      * already added (eg. someone calling ENGINE_load_blah then calling
266      * ENGINE_load_builtin_engines() perhaps).
267      */
268     ERR_clear_error();
269 }
```

257: ENGINE\_add\(\)会把dynamic engine加入到队列中：

```c
209 /* Add another "ENGINE" type into the list. */
210 int ENGINE_add(ENGINE *e)
211 {
212     int to_return = 1;
213     if (e == NULL) {
214         ENGINEerr(ENGINE_F_ENGINE_ADD, ERR_R_PASSED_NULL_PARAMETER);
215         return 0;
216     }
217     if ((e->id == NULL) || (e->name == NULL)) {
218         ENGINEerr(ENGINE_F_ENGINE_ADD, ENGINE_R_ID_OR_NAME_MISSING);
219         return 0;
220     }
221     CRYPTO_THREAD_write_lock(global_engine_lock);
222     if (!engine_list_add(e)) {
223         ENGINEerr(ENGINE_F_ENGINE_ADD, ENGINE_R_INTERNAL_LIST_ERROR);
224         to_return = 0;
225     }
226     CRYPTO_THREAD_unlock(global_engine_lock);
227     return to_return;
228 }
```

```c
 44 /*
 45  * These static functions starting with a lower case "engine_" always take
 46  * place when global_engine_lock has been locked up.
 47  */
 48 static int engine_list_add(ENGINE *e)
 49 {
 50     int conflict = 0;
 51     ENGINE *iterator = NULL;
 52
 53     if (e == NULL) {
 54         ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ERR_R_PASSED_NULL_PARAMETER);
 55         return 0;
 56     }
 57     iterator = engine_list_head;
 58     while (iterator && !conflict) {
 59         conflict = (strcmp(iterator->id, e->id) == 0);
 60         iterator = iterator->next;
 61     }
 62     if (conflict) {
 63         ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ENGINE_R_CONFLICTING_ENGINE_ID);
 64         return 0;
 65     }
 66     if (engine_list_head == NULL) {
 67         /* We are adding to an empty list. */
 68         if (engine_list_tail) {
 69             ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ENGINE_R_INTERNAL_LIST_ERROR);
 70             return 0;
 71         }
 72         engine_list_head = e;
 73         e->prev = NULL;
 74         /*
 75          * The first time the list allocates, we should register the cleanup.
 76          */
 77         engine_cleanup_add_last(engine_list_cleanup);
 78     } else {
 79         /* We are adding to the tail of an existing list. */
 80         if ((engine_list_tail == NULL) || (engine_list_tail->next != NULL)) {
 81             ENGINEerr(ENGINE_F_ENGINE_LIST_ADD, ENGINE_R_INTERNAL_LIST_ERROR);
 82             return 0;
 83         }
 84         engine_list_tail->next = e;
 85         e->prev = engine_list_tail;
 86     }
 87     /*
 88      * Having the engine in the list assumes a structural reference.
 89      */
 90     e->struct_ref++;
 91     engine_ref_debug(e, 0, 1);
 92     /* However it came to be, e is the last item in the list. */
 93     engine_list_tail = e;
 94     e->next = NULL;
 95     return 1;
 96 }
```

回到Engine load流程：

```c
 44     if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", libpath, 0)) {
 45         printf("set engine path failed\n");
 46         goto err;
 47     }
```

"SO\_PATH"对应的标签可以在找到dynamic\_cmd\_defns\[\]中找到：

```c
 41 static const ENGINE_CMD_DEFN dynamic_cmd_defns[] = {
 42     {DYNAMIC_CMD_SO_PATH,
 43      "SO_PATH",
 44      "Specifies the path to the new ENGINE shared library",
 45      ENGINE_CMD_FLAG_STRING},
 46     {DYNAMIC_CMD_NO_VCHECK,
 47      "NO_VCHECK",
 48      "Specifies to continue even if version checking fails (boolean)",
 49      ENGINE_CMD_FLAG_NUMERIC},
 50     {DYNAMIC_CMD_ID,
 51      "ID",
 52      "Specifies an ENGINE id name for loading",
 53      ENGINE_CMD_FLAG_STRING},
 54     {DYNAMIC_CMD_LIST_ADD,
 55      "LIST_ADD",
 56      "Whether to add a loaded ENGINE to the internal list (0=no,1=yes,2=mandatory)",
 57      ENGINE_CMD_FLAG_NUMERIC},
 58     {DYNAMIC_CMD_DIR_LOAD,
 59      "DIR_LOAD",
 60      "Specifies whether to load from 'DIR_ADD' directories (0=no,1=yes,2=mandatory)",
 61      ENGINE_CMD_FLAG_NUMERIC},
 62     {DYNAMIC_CMD_DIR_ADD,
 63      "DIR_ADD",
 64      "Adds a directory from which ENGINEs can be loaded",
 65      ENGINE_CMD_FLAG_STRING},
 66     {DYNAMIC_CMD_LOAD,
 67      "LOAD",
 68      "Load up the ENGINE specified by other settings",
 69      ENGINE_CMD_FLAG_NO_INPUT},
 70     {0, NULL, NULL, 0}
 71 };

```

```c
289 static int dynamic_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
290 {
291     dynamic_data_ctx *ctx = dynamic_get_data_ctx(e);
292     int initialised;
293
294     if (!ctx) {
295         ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_NOT_LOADED);
296         return 0;
297     }
298     initialised = ((ctx->dynamic_dso == NULL) ? 0 : 1);
299     /* All our control commands require the ENGINE to be uninitialised */
300     if (initialised) {
301         ENGINEerr(ENGINE_F_DYNAMIC_CTRL, ENGINE_R_ALREADY_LOADED);
302         return 0;
303     }
304     switch (cmd) {
305     case DYNAMIC_CMD_SO_PATH:
306         /* a NULL 'p' or a string of zero-length is the same thing */
307         if (p && (strlen((const char *)p) < 1))
308             p = NULL;
309         OPENSSL_free(ctx->DYNAMIC_LIBNAME);
310         if (p)
311             ctx->DYNAMIC_LIBNAME = OPENSSL_strdup(p);
312         else
313             ctx->DYNAMIC_LIBNAME = NULL;
314         return (ctx->DYNAMIC_LIBNAME ? 1 : 0);

```

可以看出ENGINE\_ctrl\_cmd\_string\(e, "SOPATH", libpath, 0\)的作用是把libpath赋值给了ctx-&gt;DYNAMICLIBNAME.

```c
 49     if (!ENGINE_ctrl_cmd_string(e, "ID", libid, 0)) {
 50         printf("set engine name failed\n");
 51         goto err;
 52     }
```

同样道理这个调用可以追踪到下述代码：

```c
318     case DYNAMIC_CMD_ID:
319         /* a NULL 'p' or a string of zero-length is the same thing */
320         if (p && (strlen((const char *)p) < 1))
321             p = NULL;
322         OPENSSL_free(ctx->engine_id);
323         if (p)
324             ctx->engine_id = OPENSSL_strdup(p);
325         else
326             ctx->engine_id = NULL;
327         return (ctx->engine_id ? 1 : 0);
```

最后的作用是设置libid到ctx-&gt;engine\_id.

最核心的功能是load:

```c
 54     if (!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
 55         printf("load engine failed\n");
 56         goto err;
 57     }
```

对应的代码：

```c
335     case DYNAMIC_CMD_LOAD:
336         return dynamic_load(e, ctx);
```

```c
396 static int dynamic_load(ENGINE *e, dynamic_data_ctx *ctx)
397 {
398     ENGINE cpy;
399     dynamic_fns fns;
400
401     if (ctx->dynamic_dso == NULL)
402         ctx->dynamic_dso = DSO_new();
403     if (ctx->dynamic_dso == NULL)
404         return 0;
405     if (!ctx->DYNAMIC_LIBNAME) {
406         if (!ctx->engine_id)
407             return 0;
408         DSO_ctrl(ctx->dynamic_dso, DSO_CTRL_SET_FLAGS,
409                  DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, NULL);
410         ctx->DYNAMIC_LIBNAME =
411             DSO_convert_filename(ctx->dynamic_dso, ctx->engine_id);
412     }
413     if (!int_load(ctx)) {
414         ENGINEerr(ENGINE_F_DYNAMIC_LOAD, ENGINE_R_DSO_NOT_FOUND);
415         DSO_free(ctx->dynamic_dso);
416         ctx->dynamic_dso = NULL;
417         return 0;
418     }
419     /* We have to find a bind function otherwise it'll always end badly */
420     if (!
421         (ctx->bind_engine =
422          (dynamic_bind_engine) DSO_bind_func(ctx->dynamic_dso,
423                                              ctx->DYNAMIC_F2))) {
424         ctx->bind_engine = NULL;
425         DSO_free(ctx->dynamic_dso);
426         ctx->dynamic_dso = NULL;
427         ENGINEerr(ENGINE_F_DYNAMIC_LOAD, ENGINE_R_DSO_FAILURE);
428         return 0;
429     }
430     /* Do we perform version checking? */
431     if (!ctx->no_vcheck) {
432         unsigned long vcheck_res = 0;
433         /*
434          * Now we try to find a version checking function and decide how to
435          * cope with failure if/when it fails.
436          */
437         ctx->v_check =
438             (dynamic_v_check_fn) DSO_bind_func(ctx->dynamic_dso,
439                                                ctx->DYNAMIC_F1);
440         if (ctx->v_check)
441             vcheck_res = ctx->v_check(OSSL_DYNAMIC_VERSION);
442         /*
443          * We fail if the version checker veto'd the load *or* if it is
444          * deferring to us (by returning its version) and we think it is too
445          * old.
446          */
447         if (vcheck_res < OSSL_DYNAMIC_OLDEST) {
448             /* Fail */
449             ctx->bind_engine = NULL;
450             ctx->v_check = NULL;
451             DSO_free(ctx->dynamic_dso);
452             ctx->dynamic_dso = NULL;
453             ENGINEerr(ENGINE_F_DYNAMIC_LOAD,
454                       ENGINE_R_VERSION_INCOMPATIBILITY);
455             return 0;
456         }
457     }
458     /*
459      * First binary copy the ENGINE structure so that we can roll back if the
460      * hand-over fails
461      */
462     memcpy(&cpy, e, sizeof(ENGINE));
463     /*
464      * Provide the ERR, "ex_data", memory, and locking callbacks so the
465      * loaded library uses our state rather than its own. FIXME: As noted in
466      * engine.h, much of this would be simplified if each area of code
467      * provided its own "summary" structure of all related callbacks. It
468      * would also increase opaqueness.
469      */
470     fns.static_state = ENGINE_get_static_state();
471     CRYPTO_get_mem_functions(&fns.mem_fns.malloc_fn, &fns.mem_fns.realloc_fn,
472                              &fns.mem_fns.free_fn);
473     /*
474      * Now that we've loaded the dynamic engine, make sure no "dynamic"
475      * ENGINE elements will show through.
476      */
477     engine_set_all_null(e);
478
479     /* Try to bind the ENGINE onto our own ENGINE structure */
480     if (!ctx->bind_engine(e, ctx->engine_id, &fns)) {
481         ctx->bind_engine = NULL;
482         ctx->v_check = NULL;
483         DSO_free(ctx->dynamic_dso);
484         ctx->dynamic_dso = NULL;
485         ENGINEerr(ENGINE_F_DYNAMIC_LOAD, ENGINE_R_INIT_FAILED);
486         /* Copy the original ENGINE structure back */
487         memcpy(e, &cpy, sizeof(ENGINE));
488         return 0;
489     }
490     /* Do we try to add this ENGINE to the internal list too? */
491     if (ctx->list_add_value > 0) {
492         if (!ENGINE_add(e)) {
493             /* Do we tolerate this or fail? */
494             if (ctx->list_add_value > 1) {
495                 /*
496                  * Fail - NB: By this time, it's too late to rollback, and
497                  * trying to do so allows the bind_engine() code to have
498                  * created leaks. We just have to fail where we are, after
499                  * the ENGINE has changed.
500                  */
501                 ENGINEerr(ENGINE_F_DYNAMIC_LOAD,
502                           ENGINE_R_CONFLICTING_ENGINE_ID);
503                 return 0;
504             }
505             /* Tolerate */
506             ERR_clear_error();
507         }
508     }
509     return 1;
510 }
```

420-429：以ctx-&gt;DYNAMIC\_F2为名字查找bind\_engine函数，ctx-&gt;DYNAMIC\_F2是啥呢？

```c
154 static int dynamic_set_data_ctx(ENGINE *e, dynamic_data_ctx **ctx)
155 {
156     dynamic_data_ctx *c = OPENSSL_zalloc(sizeof(*c));
157     int ret = 1;
158
159     if (c == NULL) {
160         ENGINEerr(ENGINE_F_DYNAMIC_SET_DATA_CTX, ERR_R_MALLOC_FAILURE);
161         return 0;
162     }
163     c->dirs = sk_OPENSSL_STRING_new_null();
164     if (c->dirs == NULL) {
165         ENGINEerr(ENGINE_F_DYNAMIC_SET_DATA_CTX, ERR_R_MALLOC_FAILURE);
166         OPENSSL_free(c);
167         return 0;
168     }
169     c->DYNAMIC_F1 = "v_check";
170     c->DYNAMIC_F2 = "bind_engine";
```

原来ctx-&gt;DYNAMIC\_F2是bind_\__engine。这个函数会在480行调用。这个函数在Intel QAT Engine中是什么呢？

```c
 975 #ifndef OPENSSL_NO_DYNAMIC_ENGINE
 976 IMPLEMENT_DYNAMIC_BIND_FN(bind_qat)
 977     IMPLEMENT_DYNAMIC_CHECK_FN()
 978 #endif 
```

QAT Eingine中用IMPLEMENT\_DYNAMIC\_BIND\_FN定义了一个函数，IMPLEMENT\_DYNAMIC\_BIND\_FN是OpenSSL中的一个宏：

```c
716 # define IMPLEMENT_DYNAMIC_BIND_FN(fn) \
717         OPENSSL_EXPORT \
718         int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \
719         OPENSSL_EXPORT \
720         int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \
721             if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; \
722             CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, \
723                                      fns->mem_fns.realloc_fn, \
724                                      fns->mem_fns.free_fn); \
725         skip_cbs: \
726             if (!fn(e, id)) return 0; \
727             return 1; }
```

这个宏定义了一个名字为bindengine\(\)的函数，这个函数会调用QAT Engine中的bind\_qat\(\)函数。这个函数的内容会在下一节中详细分析。

至此，Engine的加载完成。

