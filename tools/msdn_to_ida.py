import tkinter as tk
from tkinter import scrolledtext

def clean_text():
    input_text = input_textbox.get("1.0", tk.END)
    cleaned_text = input_text.replace("[in]", "").replace("[out]", "").replace("\n", " ")
    cleaned_text = ' '.join(cleaned_text.split())
    output_textbox.delete("1.0", tk.END)
    output_textbox.insert(tk.END, cleaned_text)
    root.clipboard_clear()
    root.clipboard_append(cleaned_text)
    root.update()  

def clear_textboxes():
    input_textbox.delete("1.0", tk.END)
    output_textbox.delete("1.0", tk.END)

root = tk.Tk()
root.title("MSDN2IDA")

input_label = tk.Label(root, text="Input:")
input_label.pack(anchor="w", padx=10, pady=(10, 0))

input_textbox = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=10)
input_textbox.pack(padx=10, pady=5)

output_label = tk.Label(root, text="Cleaned Output:")
output_label.pack(anchor="w", padx=10, pady=(10, 0))

output_textbox = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=10)
output_textbox.pack(padx=10, pady=5)
output_textbox.configure(state=tk.NORMAL)

clean_button = tk.Button(root, text="Convert", command=clean_text)
clean_button.pack(pady=5)

clear_button = tk.Button(root, text="Clear All", command=clear_textboxes)
clear_button.pack(pady=5)

root.mainloop()
