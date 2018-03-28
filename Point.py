class Point:
    def __init__ (self):
        self.X = 0;
        self.Y = 0;

    def __init__(self, x, y):
        self.X = x;
        self.Y = y;

    def move(self, dx, dy):
        self.X = self.X + dx
        self.Y = self.Y + dy

    def __str__(self):
        return "(" + str(self.X) + ", " + str(self.Y) + ")"