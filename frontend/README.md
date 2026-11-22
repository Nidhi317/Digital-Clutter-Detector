# Digital Clutter Detector frontend

This is a dependency-free HTML, CSS, and vanilla JavaScript frontend.

## Run it with the backend

The Flask backend serves this frontend and the API from the same origin. Follow [the backend setup guide](../backend/README.md), then open [http://127.0.0.1:5000](http://127.0.0.1:5000).
The API base URL defaults to the current origin. To use a same-origin reverse proxy or another API host, set the `content` of `<meta name="api-base-url">` in `index.html`. Cross-origin hosting also requires the Flask deployment to allow that origin.

## Run the static frontend only

1. Open a terminal in this `frontend` folder.
2. Start a local web server. For example, with Python installed:

   ```powershell
   py -m http.server 8000
   ```

3. Visit [http://localhost:8000](http://localhost:8000) in your browser.

Static hosting does not serve the Flask API by itself. Configure the API base URL and a matching CORS policy if you host the frontend separately; using Flask to serve the frontend is recommended. Opening `index.html` directly is not supported for API integration.

## Scan and cleanup behavior

- Entering a path and choosing **Scan folder** sends `POST /api/scan` with `{ "path": "..." }`. The backend accepts only paths inside configured scan roots.
- One copy per matching-hash group is protected automatically. The remaining copies start selected.
- **Move to quarantine** sends `POST /api/cleanup` with `{ "file_ids": [1, 2] }`. The backend only moves verified duplicate copies.
- Restoring a real quarantined file sends `POST /api/restore` with `{ "quarantine_ids": [1] }`.

Dashboard, duplicate groups, quarantine records, and scan history are read from the Flask API and SQLite database. Only the user's current checkbox selections are stored in local browser storage.
