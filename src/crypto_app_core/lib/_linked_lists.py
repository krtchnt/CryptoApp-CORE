import typing as t

from dataclasses import dataclass


Something = t.Any


# Create the node class
@dataclass(slots=True, eq=True, order=True)
class Node:
    data: Something
    next: 't.Optional[Node]' = None
    prev: 't.Optional[Node]' = None


# Create the doubly linked list class
@dataclass(slots=True, eq=True, order=True)
class LinkedList:
    head: t.Optional[Node] = None

    def __iter__(self):
        node = self.head
        while node is not None:
            yield node
            node = node.next

    def __repr__(self):
        node = self.head
        nodes: list[Node] = []
        while node is not None:
            nodes.append(node)
            node = node.next
        return ' ⮂ '.join(map(repr, nodes))

    def __len__(self):
        l = 0
        for _ in self:
            l += 1
        return l

    # Define the push method to add elements at the begining
    def push(self, new_data: Something):
        new_node = Node(new_data)
        new_node.next = self.head
        if self.head is not None:
            self.head.prev = new_node
        self.head = new_node

    # Define the append method to add elements at the end
    def append(self, new_data: Something):
        new_node = Node(new_data)
        new_node.next = None
        if self.head is None:
            new_node.prev = None
            self.head = new_node
            return
        last = self.head
        while last.next is not None:
            last = last.next
        last.next = new_node
        new_node.prev = last
        return

    # Define the method to print
    def view(self, node: t.Optional[Node]):
        while node is not None:
            print(node.data),
            _last = node
            node = node.next
