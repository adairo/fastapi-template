# Server-rendered HTML with session cookies

The application serves Jinja2 HTML pages with form posts as its only HTTP interface. Authentication uses a signed session cookie (8-day lifetime) storing the user id. Pico CSS is vendored for styling. There is no separate frontend build, no JSON API, and no bearer tokens for browser access.
