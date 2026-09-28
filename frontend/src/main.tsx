import "@fontsource-variable/ibm-plex-sans/wght.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";
import { ApiError } from "./api/client";
import { Layout } from "./components/Layout";
import "./index.css";
import { Audits } from "./pages/Audits";
import { Dashboard } from "./pages/Dashboard";
import { DevicePage } from "./pages/Device";
import { KnowledgeBase } from "./pages/KnowledgeBase";
import { NewAudit } from "./pages/NewAudit";
import { NotFound } from "./pages/NotFound";
import { Rules } from "./pages/Rules";
import { UploadResults } from "./pages/UploadResults";

const queries = new QueryClient({
  defaultOptions: {
    queries: {
      // A 4xx is an answer, not a hiccup: don't ask again.
      retry: (count, error) => !(error instanceof ApiError && error.status < 500) && count < 2,
      refetchOnWindowFocus: false,
    },
  },
});

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: "/", element: <Dashboard /> },
      { path: "/audits/new", element: <NewAudit /> },
      { path: "/audits/new/:uploadId", element: <NewAudit /> },
      { path: "/audits", element: <Audits /> },
      { path: "/uploads/:uploadId", element: <UploadResults /> },
      { path: "/devices/:jobId", element: <DevicePage /> },
      { path: "/knowledge", element: <KnowledgeBase /> },
      { path: "/knowledge/:packId", element: <KnowledgeBase /> },
      { path: "/rules", element: <Rules /> },
      { path: "*", element: <NotFound /> },
    ],
  },
]);

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root");
createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queries}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
