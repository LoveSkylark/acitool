"""
Tree building and printing utilities for ACI data structures.
"""

from typing import Dict, List, Any, Union


class ACITreeBuilder:
    """
    Helper class for building and printing hierarchical tree structures
    for ACI data visualization.
    """

    def __init__(self):
        """Initialize an empty tree."""
        self.tree: Dict[str, Any] = {}

    def add(self, *levels: str, label: str) -> None:
        """
        Add a leaf node to the tree at the specified path.

        Args:
            *levels: Variable number of hierarchy levels
            label: The leaf label to add (can contain '/' for sub-paths)

        Raises:
            ValueError: If no levels are provided

        Example:
            tree.add("tenant1", "EPG: App1", label="web/server (vlan-100)")
        """
        if not levels:
            raise ValueError("At least one level must be provided")

        *path_levels, last_level = levels
        node = self.tree

        # Navigate/create path to parent node
        for level in path_levels:
            node = node.setdefault(level, {})

        # Get or create the last level
        node = node.setdefault(last_level, {})

        # Split label by '/' and create nested structure
        parts = label.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})

        # Add the final leaf
        leaf = parts[-1]
        leaf_list = node.setdefault('_leaf', [])
        if leaf not in leaf_list:  # Avoid duplicates
            leaf_list.append(leaf)

    def print(self, label: str = None) -> None:
        """
        Print the tree structure with proper indentation.

        Args:
            label: Optional header label to print before the tree
        """
        if label:
            print(label)

        self._walk(self.tree, 0)

    def _walk(self, node: Union[Dict, List, Any], depth: int) -> None:
        """
        Recursively walk and print the tree structure.

        Args:
            node: Current node in the tree
            depth: Current indentation depth
        """
        indent = "  " * depth

        if isinstance(node, dict):
            for k, v in node.items():
                if k == "_leaf":
                    # Print leaf items at current indentation
                    for item in v:
                        print(f"{indent}{item}")
                else:
                    # Print key and recurse into children
                    print(f"{indent}{k}")
                    self._walk(v, depth + 1)
        elif isinstance(node, list):
            # Print list items
            for item in node:
                print(f"{indent}{item}")
        else:
            # Print simple value
            print(f"{indent}{node}")

    @staticmethod
    def print_tree(tree: Dict[str, Any], label: str = None) -> None:
        """
        Static method for printing a tree dictionary directly.

        This maintains backward compatibility with the old print_tree function.

        Args:
            tree: Tree dictionary to print
            label: Optional header label
        """
        if label:
            print(label)

        def walk(node, depth):
            indent = "  " * depth
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "_leaf":
                        for item in v:
                            print(f"{indent}{item}")
                    else:
                        print(f"{indent}{k}")
                        walk(v, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    print(f"{indent}{item}")
            else:
                print(f"{indent}{node}")

        walk(tree, 0)
