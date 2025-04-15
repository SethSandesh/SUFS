/* eslint-disable no-restricted-globals */

self.addEventListener("install", (event) => {
    console.log("Service Worker Installed");
    event.waitUntil(
        caches.open("static-cache").then((cache) => {
            return cache.addAll(["/", "/index.html"]);
        })
    );
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    console.log("Service Worker Activated");
});

self.addEventListener("fetch", (event) => {
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
    console.log("Fetching:", event.request.url);
});
