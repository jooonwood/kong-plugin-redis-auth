# Kong-plugin-redis-auth 

[![Build Status](https://app.travis-ci.com/jooonwood/kong-plugin-redis-auth.svg?branch=master)](https://app.travis-ci.com/jooonwood/kong-plugin-redis-auth)

Just like kong plugin `key-auth`, storage key in external redis, valid key, return json.

## Install

```bash

luarocks install kong-plugin-redis-auth

```

## How to use

### Setting

```

_format_version: "1.1"

plugins:
- name: redis-auth
  config: 
    hide_credentials: true
    redis_host: redis
    redis_port: 6379
    redis_key_prefix: 'redis-auth:'
    consumer_keys:
      - id
      - name
    anonymous: true
    anonymous_consumer: '{ "id": 10000, "type": "person", "name": "anonymous" }'
    anonymous_paths:
      - /public

services:
- name: public-service
  url: http://localhost:5000/
  routes:
  - name: public-route
    paths:
    - /public

- name: private-service
  url: https://cn.bing.com
  routes:
  - name: private-route
    paths:
    - /private


```

### Save Redis data

The following keys are used, `redis-auth:` is a key prefix string. you can change config `redis_key_prefix`'s value.

- `redis-auth:sessions` store all sessions
- `redis-auth:users:id` store user info as json
- `redis-auth:services:service-name` store a service visible to internal or specified users

```bash
  # set service hello visible to internal
  SADD redis-auth:services:hello "internal"
  # set service world visible to user id 1 or 2 or 3
  SADD redis-auth:services:world 1 2 3
  # set apikey-user-1 as user id 1's apikey
  ZADD redis-auth:sessions 1 "apikey-user-1"
  # set user id 1's info
  SET redis-auth:users:1 '{ "id": 1, "name": "user1" }'

```
