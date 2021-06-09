# BlackSheepOptimizedAccountSystem
BSOAS uses the most optimized way to relay information over http, Utilizing tuples and paired with the the Black Sheep web framework and SQLalchemy delivering a safe and secure barebones authentication system. 
BSOAS uses the fastest ASGI framework (Black Sheep) paired with uvicorn according to http://klen.github.io/py-frameworks-bench/ (almost 8x faster than django).

avg response time of endpoints on LAN:

/account/auth/login -> Success: 1 ms Failure: 1 ms

/account/auth/register -> Success: 4-5 ms Failure: 3-4 ms

/account/auth/session -> Success: 0.5 ms Failure: 0-0.5 ms


If you find any changes that can optimize the system, please open a pull request and I will get to it ASAP.
