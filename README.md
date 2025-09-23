## DiffRays

# Version History

### 0.1 - Alpha

**Added Features:**  
- ✅ Usage of DiffLib to generate an HTML file.  
- ✅ HTML file with modified CSS.  

---

### 0.2 - Beta

**Added Features:**  
- ✅ Implemented Dark Mode as Dracula theme.  

---

### 0.3 - Gamma

**Added Features:**  
- ✅ Implemented Flask Application for dynamic code diffing.  

**Suggested Improvements:**  
- ✅ Highlight the whole line when there is new code (green), instead of just words.  
- ✅ Change title of the inputs from *old/new* to *original/modified*.  

---

### 0.4 - Delta 

**Added Features:**  
- ✅ Highlight the whole line when there is new code (green).  
- ✅ Added “Character Level Highlight” button.  

**Bug:**  
- ❌ Top bar scrolls with content; needs fixing.  

---

### 0.5 - Epsilon 

**Added Features:**  
- ✅ Created a Pseudocode extractor using IDA Domain API.
- ✅ Store all the result in Sqlite3 DB?

---

### 0.6 - Zeta 

**Added Features:** 
- ✅ Create parser for SQLITE3 database and perform diff between two binaries's functions using difflib and store the result as HTML.  
- ✅ Decide final result format: HTML with CSS vs MD.  
- ~~Maybe create a full-fledged local HTML application to view results instead of Flask-based app.~~
- ✅ Created a Flask based server to view the result.

---

### 0.7 - Eta 

**Added Features:** 
- ✅ Make a new web application with better visualization to view all data.  
- ✅ Implement % of code changed.  
- ✅ Similar to Bindiff visuals: https://insinuator.net/wp-content/uploads/2013/07/diff-result.png  
- ✅ Implement search feature to search for functions.  

---

### 0.8 - Theta

**Added Features:** 
- ✅ Ensure headless downloads symbols from servers.  
- ✅ Add basic information about the binary to the dashboard like base address, md5 hash, format, module, etc.. 
- ✅ Store more information about the functions in the database and show them in webpage too like: Address, Signature.

---

### 0.9 - Iota

**Added Features:** 
- ✅ Make IDA headless plugin script which takes 2 binaries as input and creates final output as SQLite3.  
- ✅ Make the application portal, that means make the server feature of the application works without IDA.
- ✅ Add `--debug` then only display the logs.
- ✅ Add a proper progress bar and better visual output for python.
- ✅ Add `--log` to store the log results in a file, dont ask for name use `log_<old_file>_<new_file>.txt`.
- ✅ Make a better `--help` output.
- ✅ Add project banner to the python script.
- ✅ Dont store it as output.sqlite instead `result_<old_file>_<new_file>_<timestamp>.sqlite`

---

### 1.0 - Kappa

**To Do:**  
- ✅ Create a logo for the project.  
- ✅ LIVE

---

### 1.1 - Lambda

**To Do:**  
- ✅ Implement smart sorting based on blocks

---

### 1.2 - Mu

**To Do:**  
- ✅ Move all the diffing results to DB

---

### 1.3 - Nu

**To Do:**
- ✅ Searching function name box is making the site slow
- ✅ S.Ratio calculation is wrong
- ✅ Opening Signature in the server makes the site slow

---

### 1.4 - Xi

- ✅ Function Name need to be wrapped in all 3 pages
- ✅ Add Time in cli to show the elapsed time to complete the task
- ✅ Implement Pagination for loading the functions better.
 
---

### 1.5 - Omicron


- ⬜ Implement Auto Diffing feature

---