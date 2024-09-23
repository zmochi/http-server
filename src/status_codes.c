#include <src/status_codes.h>

static const int   smallest_code = 100;
static const char *status_codes_arr[];

const char *stringify_statuscode(http_status_code status_code) {
    return status_codes_arr[status_code - smallest_code];
}

static const char *status_codes_arr[] = {
    // code: 100
    "Continue",
    // code: 101
    "Switching Protocols",
    // code: 102
    "Processing",
    // code: 103
    "Early Hints",
    // code: 104
    "",
    // code: 105
    "",
    // code: 106
    "",
    // code: 107
    "",
    // code: 108
    "",
    // code: 109
    "",
    // code: 110
    "",
    // code: 111
    "",
    // code: 112
    "",
    // code: 113
    "",
    // code: 114
    "",
    // code: 115
    "",
    // code: 116
    "",
    // code: 117
    "",
    // code: 118
    "",
    // code: 119
    "",
    // code: 120
    "",
    // code: 121
    "",
    // code: 122
    "",
    // code: 123
    "",
    // code: 124
    "",
    // code: 125
    "",
    // code: 126
    "",
    // code: 127
    "",
    // code: 128
    "",
    // code: 129
    "",
    // code: 130
    "",
    // code: 131
    "",
    // code: 132
    "",
    // code: 133
    "",
    // code: 134
    "",
    // code: 135
    "",
    // code: 136
    "",
    // code: 137
    "",
    // code: 138
    "",
    // code: 139
    "",
    // code: 140
    "",
    // code: 141
    "",
    // code: 142
    "",
    // code: 143
    "",
    // code: 144
    "",
    // code: 145
    "",
    // code: 146
    "",
    // code: 147
    "",
    // code: 148
    "",
    // code: 149
    "",
    // code: 150
    "",
    // code: 151
    "",
    // code: 152
    "",
    // code: 153
    "",
    // code: 154
    "",
    // code: 155
    "",
    // code: 156
    "",
    // code: 157
    "",
    // code: 158
    "",
    // code: 159
    "",
    // code: 160
    "",
    // code: 161
    "",
    // code: 162
    "",
    // code: 163
    "",
    // code: 164
    "",
    // code: 165
    "",
    // code: 166
    "",
    // code: 167
    "",
    // code: 168
    "",
    // code: 169
    "",
    // code: 170
    "",
    // code: 171
    "",
    // code: 172
    "",
    // code: 173
    "",
    // code: 174
    "",
    // code: 175
    "",
    // code: 176
    "",
    // code: 177
    "",
    // code: 178
    "",
    // code: 179
    "",
    // code: 180
    "",
    // code: 181
    "",
    // code: 182
    "",
    // code: 183
    "",
    // code: 184
    "",
    // code: 185
    "",
    // code: 186
    "",
    // code: 187
    "",
    // code: 188
    "",
    // code: 189
    "",
    // code: 190
    "",
    // code: 191
    "",
    // code: 192
    "",
    // code: 193
    "",
    // code: 194
    "",
    // code: 195
    "",
    // code: 196
    "",
    // code: 197
    "",
    // code: 198
    "",
    // code: 199
    "",
    // code: 200
    "OK",
    // code: 201
    "Created",
    // code: 202
    "Accepted",
    // code: 203
    "Non-Authoritative Information",
    // code: 204
    "No Content",
    // code: 205
    "Reset Content",
    // code: 206
    "Partial Content",
    // code: 207
    "Multi-Status",
    // code: 208
    "Already Reported",
    // code: 209
    "",
    // code: 210
    "",
    // code: 211
    "",
    // code: 212
    "",
    // code: 213
    "",
    // code: 214
    "",
    // code: 215
    "",
    // code: 216
    "",
    // code: 217
    "",
    // code: 218
    "",
    // code: 219
    "",
    // code: 220
    "",
    // code: 221
    "",
    // code: 222
    "",
    // code: 223
    "",
    // code: 224
    "",
    // code: 225
    "",
    // code: 226
    "IM Used",
    // code: 227
    "",
    // code: 228
    "",
    // code: 229
    "",
    // code: 230
    "",
    // code: 231
    "",
    // code: 232
    "",
    // code: 233
    "",
    // code: 234
    "",
    // code: 235
    "",
    // code: 236
    "",
    // code: 237
    "",
    // code: 238
    "",
    // code: 239
    "",
    // code: 240
    "",
    // code: 241
    "",
    // code: 242
    "",
    // code: 243
    "",
    // code: 244
    "",
    // code: 245
    "",
    // code: 246
    "",
    // code: 247
    "",
    // code: 248
    "",
    // code: 249
    "",
    // code: 250
    "",
    // code: 251
    "",
    // code: 252
    "",
    // code: 253
    "",
    // code: 254
    "",
    // code: 255
    "",
    // code: 256
    "",
    // code: 257
    "",
    // code: 258
    "",
    // code: 259
    "",
    // code: 260
    "",
    // code: 261
    "",
    // code: 262
    "",
    // code: 263
    "",
    // code: 264
    "",
    // code: 265
    "",
    // code: 266
    "",
    // code: 267
    "",
    // code: 268
    "",
    // code: 269
    "",
    // code: 270
    "",
    // code: 271
    "",
    // code: 272
    "",
    // code: 273
    "",
    // code: 274
    "",
    // code: 275
    "",
    // code: 276
    "",
    // code: 277
    "",
    // code: 278
    "",
    // code: 279
    "",
    // code: 280
    "",
    // code: 281
    "",
    // code: 282
    "",
    // code: 283
    "",
    // code: 284
    "",
    // code: 285
    "",
    // code: 286
    "",
    // code: 287
    "",
    // code: 288
    "",
    // code: 289
    "",
    // code: 290
    "",
    // code: 291
    "",
    // code: 292
    "",
    // code: 293
    "",
    // code: 294
    "",
    // code: 295
    "",
    // code: 296
    "",
    // code: 297
    "",
    // code: 298
    "",
    // code: 299
    "",
    // code: 300
    "Multiple Choices",
    // code: 301
    "Moved Permanently",
    // code: 302
    "Found",
    // code: 303
    "See Other",
    // code: 304
    "Not Modified",
    // code: 305
    "Use Proxy",
    // code: 306
    "(Unused)",
    // code: 307
    "Temporary Redirect",
    // code: 308
    "Permanent Redirect",
    // code: 309
    "",
    // code: 310
    "",
    // code: 311
    "",
    // code: 312
    "",
    // code: 313
    "",
    // code: 314
    "",
    // code: 315
    "",
    // code: 316
    "",
    // code: 317
    "",
    // code: 318
    "",
    // code: 319
    "",
    // code: 320
    "",
    // code: 321
    "",
    // code: 322
    "",
    // code: 323
    "",
    // code: 324
    "",
    // code: 325
    "",
    // code: 326
    "",
    // code: 327
    "",
    // code: 328
    "",
    // code: 329
    "",
    // code: 330
    "",
    // code: 331
    "",
    // code: 332
    "",
    // code: 333
    "",
    // code: 334
    "",
    // code: 335
    "",
    // code: 336
    "",
    // code: 337
    "",
    // code: 338
    "",
    // code: 339
    "",
    // code: 340
    "",
    // code: 341
    "",
    // code: 342
    "",
    // code: 343
    "",
    // code: 344
    "",
    // code: 345
    "",
    // code: 346
    "",
    // code: 347
    "",
    // code: 348
    "",
    // code: 349
    "",
    // code: 350
    "",
    // code: 351
    "",
    // code: 352
    "",
    // code: 353
    "",
    // code: 354
    "",
    // code: 355
    "",
    // code: 356
    "",
    // code: 357
    "",
    // code: 358
    "",
    // code: 359
    "",
    // code: 360
    "",
    // code: 361
    "",
    // code: 362
    "",
    // code: 363
    "",
    // code: 364
    "",
    // code: 365
    "",
    // code: 366
    "",
    // code: 367
    "",
    // code: 368
    "",
    // code: 369
    "",
    // code: 370
    "",
    // code: 371
    "",
    // code: 372
    "",
    // code: 373
    "",
    // code: 374
    "",
    // code: 375
    "",
    // code: 376
    "",
    // code: 377
    "",
    // code: 378
    "",
    // code: 379
    "",
    // code: 380
    "",
    // code: 381
    "",
    // code: 382
    "",
    // code: 383
    "",
    // code: 384
    "",
    // code: 385
    "",
    // code: 386
    "",
    // code: 387
    "",
    // code: 388
    "",
    // code: 389
    "",
    // code: 390
    "",
    // code: 391
    "",
    // code: 392
    "",
    // code: 393
    "",
    // code: 394
    "",
    // code: 395
    "",
    // code: 396
    "",
    // code: 397
    "",
    // code: 398
    "",
    // code: 399
    "",
    // code: 400
    "Bad Request",
    // code: 401
    "Unauthorized",
    // code: 402
    "Payment Required",
    // code: 403
    "Forbidden",
    // code: 404
    "Not Found",
    // code: 405
    "Method Not Allowed",
    // code: 406
    "Not Acceptable",
    // code: 407
    "Proxy Authentication Required",
    // code: 408
    "Request Timeout",
    // code: 409
    "Conflict",
    // code: 410
    "Gone",
    // code: 411
    "Length Required",
    // code: 412
    "Precondition Failed",
    // code: 413
    "Content Too Large",
    // code: 414
    "URI Too Long",
    // code: 415
    "Unsupported Media Type",
    // code: 416
    "Range Not Satisfiable",
    // code: 417
    "Expectation Failed",
    // code: 418
    "(Unused)",
    // code: 419
    "",
    // code: 420
    "",
    // code: 421
    "Misdirected Request",
    // code: 422
    "Unprocessable Content",
    // code: 423
    "Locked",
    // code: 424
    "Failed Dependency",
    // code: 425
    "Too Early",
    // code: 426
    "Upgrade Required",
    // code: 427
    "",
    // code: 428
    "Precondition Required",
    // code: 429
    "Too Many Requests",
    // code: 430
    "",
    // code: 431
    "Request Header Fields Too Large",
    // code: 432
    "",
    // code: 433
    "",
    // code: 434
    "",
    // code: 435
    "",
    // code: 436
    "",
    // code: 437
    "",
    // code: 438
    "",
    // code: 439
    "",
    // code: 440
    "",
    // code: 441
    "",
    // code: 442
    "",
    // code: 443
    "",
    // code: 444
    "",
    // code: 445
    "",
    // code: 446
    "",
    // code: 447
    "",
    // code: 448
    "",
    // code: 449
    "",
    // code: 450
    "",
    // code: 451
    "Unavailable For Legal Reasons",
    // code: 452
    "",
    // code: 453
    "",
    // code: 454
    "",
    // code: 455
    "",
    // code: 456
    "",
    // code: 457
    "",
    // code: 458
    "",
    // code: 459
    "",
    // code: 460
    "",
    // code: 461
    "",
    // code: 462
    "",
    // code: 463
    "",
    // code: 464
    "",
    // code: 465
    "",
    // code: 466
    "",
    // code: 467
    "",
    // code: 468
    "",
    // code: 469
    "",
    // code: 470
    "",
    // code: 471
    "",
    // code: 472
    "",
    // code: 473
    "",
    // code: 474
    "",
    // code: 475
    "",
    // code: 476
    "",
    // code: 477
    "",
    // code: 478
    "",
    // code: 479
    "",
    // code: 480
    "",
    // code: 481
    "",
    // code: 482
    "",
    // code: 483
    "",
    // code: 484
    "",
    // code: 485
    "",
    // code: 486
    "",
    // code: 487
    "",
    // code: 488
    "",
    // code: 489
    "",
    // code: 490
    "",
    // code: 491
    "",
    // code: 492
    "",
    // code: 493
    "",
    // code: 494
    "",
    // code: 495
    "",
    // code: 496
    "",
    // code: 497
    "",
    // code: 498
    "",
    // code: 499
    "",
    // code: 500
    "Internal Server Error",
    // code: 501
    "Not Implemented",
    // code: 502
    "Bad Gateway",
    // code: 503
    "Service Unavailable",
    // code: 504
    "Gateway Timeout",
    // code: 505
    "HTTP Version Not Supported",
    // code: 506
    "Variant Also Negotiates",
    // code: 507
    "Insufficient Storage",
    // code: 508
    "Loop Detected",
    // code: 509
    "",
    // code: 510
    "Not Extended (OBSOLETED)",
    // code: 511
    "Network Authentication Required",
    // code: 512
    "",
    // code: 513
    "",
    // code: 514
    "",
    // code: 515
    "",
    // code: 516
    "",
    // code: 517
    "",
    // code: 518
    "",
    // code: 519
    "",
    // code: 520
    "",
    // code: 521
    "",
    // code: 522
    "",
    // code: 523
    "",
    // code: 524
    "",
    // code: 525
    "",
    // code: 526
    "",
    // code: 527
    "",
    // code: 528
    "",
    // code: 529
    "",
    // code: 530
    "",
    // code: 531
    "",
    // code: 532
    "",
    // code: 533
    "",
    // code: 534
    "",
    // code: 535
    "",
    // code: 536
    "",
    // code: 537
    "",
    // code: 538
    "",
    // code: 539
    "",
    // code: 540
    "",
    // code: 541
    "",
    // code: 542
    "",
    // code: 543
    "",
    // code: 544
    "",
    // code: 545
    "",
    // code: 546
    "",
    // code: 547
    "",
    // code: 548
    "",
    // code: 549
    "",
    // code: 550
    "",
    // code: 551
    "",
    // code: 552
    "",
    // code: 553
    "",
    // code: 554
    "",
    // code: 555
    "",
    // code: 556
    "",
    // code: 557
    "",
    // code: 558
    "",
    // code: 559
    "",
    // code: 560
    "",
    // code: 561
    "",
    // code: 562
    "",
    // code: 563
    "",
    // code: 564
    "",
    // code: 565
    "",
    // code: 566
    "",
    // code: 567
    "",
    // code: 568
    "",
    // code: 569
    "",
    // code: 570
    "",
    // code: 571
    "",
    // code: 572
    "",
    // code: 573
    "",
    // code: 574
    "",
    // code: 575
    "",
    // code: 576
    "",
    // code: 577
    "",
    // code: 578
    "",
    // code: 579
    "",
    // code: 580
    "",
    // code: 581
    "",
    // code: 582
    "",
    // code: 583
    "",
    // code: 584
    "",
    // code: 585
    "",
    // code: 586
    "",
    // code: 587
    "",
    // code: 588
    "",
    // code: 589
    "",
    // code: 590
    "",
    // code: 591
    "",
    // code: 592
    "",
    // code: 593
    "",
    // code: 594
    "",
    // code: 595
    "",
    // code: 596
    "",
    // code: 597
    "",
    // code: 598
    "",
    // code: 599
    "",
};
