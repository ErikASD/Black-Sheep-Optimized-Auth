# Black Sheep Optimized Auth
BSOA uses the most optimized way to relay information over http, Utilizing tuples and paired with the the Black Sheep web framework and SQLalchemy delivering a safe and secure barebones authentication system. 
BSOA uses the fastest available python ASGI framework (Black Sheep, according to http://klen.github.io/py-frameworks-bench/) paired with uvicorn which is almost 8x faster than Django and 2x the speed of FastAPI.

to create a normal Black Sheep project with a template https://github.com/Neoteroi/BlackSheepMVC

avg response time of endpoints on LAN:

/account/auth/register -> Success: 4-5 ms Failure: 3-4 ms

/account/auth/login -> Success: 1 ms Failure: 1 ms

/account/auth/session -> Success: 0.5 ms Failure: 0-0.5 ms


If you find any changes that can optimize the system, please open a pull request with them and I will get to them ASAP.
