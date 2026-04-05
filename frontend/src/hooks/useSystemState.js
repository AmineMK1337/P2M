import { useEffect, useRef, useState } from "react";
import { fetchSystemState } from "../services/api";
import { createMockSystemState } from "../data/mockData";

export function useSystemState(intervalMs = 2500) {
  const [state, setState] = useState(() => createMockSystemState());
  const [loading, setLoading] = useState(true);
  const [source, setSource] = useState("boot");
  const [lastUpdated, setLastUpdated] = useState("-");
  const latestStateRef = useRef(state);

  useEffect(() => {
    latestStateRef.current = state;
  }, [state]);

  useEffect(() => {
    let timer;
    let active = true;

    const sync = async () => {
      try {
        const { state: next, source: nextSource } = await fetchSystemState(latestStateRef.current);
        if (!active) return;

        setState((prev) => {
          const prevMap = new Map((prev.features.items || []).map((item) => [item.key, item.value]));
          const mapped = (next.features.items || []).map((item) => ({
            ...item,
            changed: prevMap.has(item.key) && prevMap.get(item.key) !== item.value
          }));

          return {
            ...next,
            features: {
              ...next.features,
              items: mapped
            }
          };
        });

        setSource(nextSource);
        setLastUpdated(new Date().toLocaleTimeString());
      } catch {
        if (!active) return;
        setState((prev) => createMockSystemState(prev));
        setSource("mock-fallback");
        setLastUpdated(new Date().toLocaleTimeString());
      } finally {
        if (active) setLoading(false);
      }
    };

    sync();
    timer = setInterval(sync, intervalMs);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [intervalMs]);

  return { state, loading, source, lastUpdated };
}
