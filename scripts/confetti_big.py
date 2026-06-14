#!/usr/bin/env python3
import tkinter as tk
import random
import time

def run_confetti(animation_time=8, hold_time=30, particles=800):
    root = tk.Tk()
    root.overrideredirect(True)
    root.attributes('-topmost', True)
    w = root.winfo_screenwidth()
    h = root.winfo_screenheight()
    root.geometry(f"{w}x{h}+0+0")

    canvas = tk.Canvas(root, width=w, height=h, bg='black')
    canvas.pack()

    colors = ['#ffb6c1', '#ffc0cb', '#ff69b4', '#ff1493', '#ff7eb6']
    particles_list = []

    for i in range(particles):
        x = random.randint(0, w)
        y = random.randint(-h//2, h)
        size = random.randint(4, 18)
        color = random.choice(colors)
        oval = canvas.create_oval(x, y, x+size, y+size, fill=color, outline='')
        vx = random.uniform(-3, 3)
        vy = random.uniform(2, 9)
        particles_list.append([oval, vx, vy])

    start = time.time()

    def animate():
        now = time.time()
        elapsed = now - start
        for p in particles_list:
            oval, vx, vy = p
            canvas.move(oval, vx, vy)
            coords = canvas.coords(oval)
            if coords:
                if coords[0] > w:
                    canvas.move(oval, -w-20, 0)
                if coords[2] < 0:
                    canvas.move(oval, w+20, 0)
                if coords[1] > h:
                    canvas.move(oval, 0, -h-40)

        if elapsed < animation_time:
            root.after(33, animate)

    root.after(0, animate)
    root.after(int((animation_time + hold_time) * 1000), root.destroy)
    try:
        root.mainloop()
    except Exception:
        pass

if __name__ == '__main__':
    try:
        run_confetti()
    except Exception:
        pass
