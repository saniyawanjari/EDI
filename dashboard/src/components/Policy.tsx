import { useEffect, useState } from "react";
import { getPolicy } from "../api";

export default function Policy() {
  const [text, setText] = useState("Loading...");
  useEffect(() => {
    getPolicy()
      .then((p) => setText(p.policy))
      .catch((e: unknown) => setText(`Cannot load policy: ${e instanceof Error ? e.message : String(e)}`));
  }, []);
  return <pre className="code">{text}</pre>;
}
