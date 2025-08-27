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
- ⬜ Store all the result in Sqlite3 DB?

---

### 0.6 - Zeta 

**To Do:**  
- ⬜ Create parser for SQLITE3 database and perform diff between two binaries's functions using difflib and store the result as HTML.  
- ⬜ Decide final result format: HTML with CSS vs MD.  
- ⬜ Maybe create a full-fledged local HTML application to view results instead of Flask-based app.  

---

### 0.7 - Eta 

**To Do:**  
- ⬜ Make a new web application with better visualization to view all data.  
- ⬜ Implement % of code changed.  
- ⬜ Similar to Bindiff visuals: ![example](https://insinuator.net/wp-content/uploads/2013/07/diff-result.png)  
- ⬜ Implement search feature to search for functions.  

---

### 0.8 - Theta

**To Do:**  
- ⬜ Make IDA headless plugin script which takes 2 binaries as input and creates final output instead of SQLite3.  
- ⬜ Ensure headless downloads symbols from servers.  
- ⬜ Create a logo for the project.  