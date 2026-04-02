/**
 * Exclusive XML canonicalization (http://www.w3.org/2001/10/xml-exc-c14n#).
 * Ported from xml-crypto's ExclusiveCanonicalization (MIT), trimmed to what
 * this package uses: `new ExclusiveCanonicalization().process(elem)`.
 *
 * Attribution: see NOTICE in the repository root (derived from xml-crypto).
 */

function isArrayHasLength(array: unknown): array is unknown[] {
  return Array.isArray(array) && array.length > 0;
}

const xmlSpecialToEncodedAttribute: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  '"': "&quot;",
  "\r": "&#xD;",
  "\n": "&#xA;",
  "\t": "&#x9;",
};

const xmlSpecialToEncodedText: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  "\r": "&#xD;",
};

function encodeSpecialCharactersInAttribute(attributeValue: string): string {
  return attributeValue.replace(/([&<"\r\n\t])/g, function (_str, item: string) {
    return xmlSpecialToEncodedAttribute[item];
  });
}

function encodeSpecialCharactersInText(text: string): string {
  return text.replace(/([&<>\r])/g, function (_str, item: string) {
    return xmlSpecialToEncodedText[item];
  });
}

function findChildren(node: any, localName: string, namespace?: string | null) {
  const element = node.documentElement ?? node;
  const res: any[] = [];
  for (let i = 0; i < element.childNodes.length; i++) {
    const child = element.childNodes[i];
    if (
      isElementNode(child) &&
      child.localName === localName &&
      (child.namespaceURI === namespace || namespace == null)
    ) {
      res.push(child);
    }
  }
  return res;
}

function isCommentNode(node: any): boolean {
  return node && node.nodeType === 8;
}

function isElementNode(node: any): boolean {
  return node && node.nodeType === 1;
}

function isPrefixInScope(
  prefixesInScope: { prefix: string; namespaceURI: string }[],
  prefix: string,
  namespaceURI: string
) {
  let ret = false;
  prefixesInScope.forEach(function (pf) {
    if (pf.prefix === prefix && pf.namespaceURI === namespaceURI) {
      ret = true;
    }
  });
  return ret;
}

export class ExclusiveCanonicalization {
  includeComments = false;

  attrCompare(a: any, b: any) {
    if (!a.namespaceURI && b.namespaceURI) {
      return -1;
    }
    if (!b.namespaceURI && a.namespaceURI) {
      return 1;
    }
    const left = a.namespaceURI + a.localName;
    const right = b.namespaceURI + b.localName;
    if (left === right) {
      return 0;
    } else if (left < right) {
      return -1;
    } else {
      return 1;
    }
  }

  nsCompare(a: { prefix: string }, b: { prefix: string }) {
    const attr1 = a.prefix;
    const attr2 = b.prefix;
    if (attr1 === attr2) {
      return 0;
    }
    return attr1.localeCompare(attr2);
  }

  renderAttrs(node: any) {
    let i: number;
    let attr: any;
    const res: string[] = [];
    const attrListToRender: any[] = [];
    if (isCommentNode(node)) {
      return this.renderComment(node);
    }
    if (node.attributes) {
      for (i = 0; i < node.attributes.length; ++i) {
        attr = node.attributes[i];
        if (attr.name.indexOf("xmlns") === 0) {
          continue;
        }
        attrListToRender.push(attr);
      }
    }
    attrListToRender.sort(this.attrCompare);
    for (attr of attrListToRender) {
      res.push(
        " ",
        attr.name,
        '="',
        encodeSpecialCharactersInAttribute(attr.value),
        '"'
      );
    }
    return res.join("");
  }

  renderNs(
    node: any,
    prefixesInScope: { prefix: string; namespaceURI: string }[],
    defaultNs: string,
    defaultNsForPrefix: Record<string, string>,
    inclusiveNamespacesPrefixList: string[]
  ) {
    let i: number;
    let attr: any;
    const res: string[] = [];
    let newDefaultNs = defaultNs;
    const nsListToRender: { prefix: string; namespaceURI: string }[] = [];
    const currNs = node.namespaceURI || "";
    if (node.prefix) {
      if (
        !isPrefixInScope(
          prefixesInScope,
          node.prefix,
          node.namespaceURI || defaultNsForPrefix[node.prefix]
        )
      ) {
        nsListToRender.push({
          prefix: node.prefix,
          namespaceURI: node.namespaceURI || defaultNsForPrefix[node.prefix],
        });
        prefixesInScope.push({
          prefix: node.prefix,
          namespaceURI: node.namespaceURI || defaultNsForPrefix[node.prefix],
        });
      }
    } else if (defaultNs !== currNs) {
      newDefaultNs = node.namespaceURI;
      res.push(' xmlns="', newDefaultNs, '"');
    }
    if (node.attributes) {
      for (i = 0; i < node.attributes.length; ++i) {
        attr = node.attributes[i];
        if (
          attr.prefix &&
          !isPrefixInScope(prefixesInScope, attr.localName, attr.value) &&
          inclusiveNamespacesPrefixList.indexOf(attr.localName) >= 0
        ) {
          nsListToRender.push({ prefix: attr.localName, namespaceURI: attr.value });
          prefixesInScope.push({ prefix: attr.localName, namespaceURI: attr.value });
        }
        if (
          attr.prefix &&
          !isPrefixInScope(prefixesInScope, attr.prefix, attr.namespaceURI) &&
          attr.prefix !== "xmlns" &&
          attr.prefix !== "xml"
        ) {
          nsListToRender.push({ prefix: attr.prefix, namespaceURI: attr.namespaceURI });
          prefixesInScope.push({ prefix: attr.prefix, namespaceURI: attr.namespaceURI });
        }
      }
    }
    nsListToRender.sort(this.nsCompare);
    for (const p of nsListToRender) {
      res.push(" xmlns:", p.prefix, '="', p.namespaceURI, '"');
    }
    return { rendered: res.join(""), newDefaultNs: newDefaultNs };
  }

  processInner(
    node: any,
    prefixesInScope: { prefix: string; namespaceURI: string }[],
    defaultNs: string,
    defaultNsForPrefix: Record<string, string>,
    inclusiveNamespacesPrefixList: string[]
  ): string {
    if (isCommentNode(node)) {
      return this.renderComment(node);
    }
    if (node.data) {
      return encodeSpecialCharactersInText(node.data);
    }
    if (isElementNode(node)) {
      let i: number;
      let pfxCopy: { prefix: string; namespaceURI: string }[];
      const ns = this.renderNs(
        node,
        prefixesInScope,
        defaultNs,
        defaultNsForPrefix,
        inclusiveNamespacesPrefixList
      );
      const res: string[] = [
        "<",
        node.tagName,
        ns.rendered,
        this.renderAttrs(node),
        ">",
      ];
      for (i = 0; i < node.childNodes.length; ++i) {
        pfxCopy = prefixesInScope.slice(0);
        res.push(
          this.processInner(
            node.childNodes[i],
            pfxCopy,
            ns.newDefaultNs,
            defaultNsForPrefix,
            inclusiveNamespacesPrefixList
          )
        );
      }
      res.push("</", node.tagName, ">");
      return res.join("");
    }
    throw new Error(`Unable to exclusive canonicalize node type: ${node.nodeType}`);
  }

  renderComment(node: any) {
    if (!this.includeComments) {
      return "";
    }
    const isOutsideDocument = node.ownerDocument === node.parentNode;
    let isBeforeDocument = false;
    let isAfterDocument = false;
    if (isOutsideDocument) {
      let nextNode = node;
      let previousNode = node;
      while (nextNode != null) {
        if (nextNode === node.ownerDocument.documentElement) {
          isBeforeDocument = true;
          break;
        }
        nextNode = nextNode.nextSibling;
      }
      while (previousNode != null) {
        if (previousNode === node.ownerDocument.documentElement) {
          isAfterDocument = true;
          break;
        }
        previousNode = previousNode.previousSibling;
      }
    }
    const afterDocument = isAfterDocument ? "\n" : "";
    const beforeDocument = isBeforeDocument ? "\n" : "";
    const encodedText = encodeSpecialCharactersInText(node.data);
    return `${afterDocument}<!--${encodedText}-->${beforeDocument}`;
  }

  process(elem: any, options?: any) {
    options = options || {};
    let inclusiveNamespacesPrefixList =
      options.inclusiveNamespacesPrefixList || [];
    const defaultNs = options.defaultNs || "";
    const defaultNsForPrefix = options.defaultNsForPrefix || {};
    const ancestorNamespaces = options.ancestorNamespaces || [];

    if (!isArrayHasLength(inclusiveNamespacesPrefixList)) {
      const CanonicalizationMethod = findChildren(elem, "CanonicalizationMethod");
      if (CanonicalizationMethod.length !== 0) {
        const inclusiveNamespaces = findChildren(
          CanonicalizationMethod[0],
          "InclusiveNamespaces"
        );
        if (inclusiveNamespaces.length !== 0) {
          inclusiveNamespacesPrefixList = (
            inclusiveNamespaces[0].getAttribute("PrefixList") || ""
          ).split(" ");
        }
      }
    }

    if (isArrayHasLength(inclusiveNamespacesPrefixList)) {
      inclusiveNamespacesPrefixList.forEach(function (prefix: string) {
        if (ancestorNamespaces) {
          ancestorNamespaces.forEach(function (ancestorNamespace: {
            prefix: string;
            namespaceURI: string;
          }) {
            if (prefix === ancestorNamespace.prefix) {
              elem.setAttributeNS(
                "http://www.w3.org/2000/xmlns/",
                `xmlns:${prefix}`,
                ancestorNamespace.namespaceURI
              );
            }
          });
        }
      });
    }
    return this.processInner(
      elem,
      [],
      defaultNs,
      defaultNsForPrefix,
      inclusiveNamespacesPrefixList
    );
  }

  getAlgorithmName() {
    return "http://www.w3.org/2001/10/xml-exc-c14n#";
  }
}
