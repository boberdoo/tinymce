export type NamespaceType = 'html' | 'svg';

export interface NamespaceTracker {
  readonly track: (node: Node) => NamespaceType;
  readonly current: () => NamespaceType;
  readonly reset: () => void;
}

export const isNonHtmlElementRootName = (name: string): boolean => name.toLowerCase() === 'svg';

export const isNonHtmlElementRoot = (node: Node): boolean => isNonHtmlElementRootName(node.nodeName);

export const toScopeType = (node: Node | undefined): NamespaceType => node?.nodeName === 'svg' ? 'svg' : 'html';

export const namespaceElements = [ 'svg' ];

export const createNamespaceTracker = (): NamespaceTracker => {
  let scopes: Node[] = [];

  const peek = () => scopes[scopes.length - 1];

  const track = (node: Node): NamespaceType => {
    // Leave every scope that the node is outside of, since nested or sibling roots can leave multiple scopes to close
    while (scopes.length > 0 && !peek().contains(node)) {
      scopes.pop();
    }

    if (isNonHtmlElementRoot(node)) {
      scopes.push(node);
    }

    return toScopeType(peek());
  };

  const current = () => toScopeType(peek());

  const reset = () => {
    scopes = [];
  };

  return {
    track,
    current,
    reset
  };
};
