```
| lookup cidr_lookups cidr AS src_ip OUTPUT cidr as wl_cidr
| eval is_whitelist = if(cidrmatch(wl_cidr, src_ip), 1, 0)
```

