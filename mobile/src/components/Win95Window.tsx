import React from "react";
import { Window, WindowHeader, WindowContent, Button } from "react95";
import styled from "styled-components";

interface Win95WindowProps {
  title: string;
  onClose?: () => void;
  children: React.ReactNode;
  style?: React.CSSProperties;
}

const WindowWrapper = styled.div`
  max-width: 420px;
  width: 100%;
  margin: 0 auto;
  min-height: calc(100vh - 32px);
  display: flex;
  flex-direction: column;
`;

const StyledWindowHeader = styled(WindowHeader)`
  display: flex;
  align-items: center;
  justify-content: space-between;
`;

const TitleText = styled.span`
  font-weight: bold;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const CloseButton = styled(Button)`
  margin-left: auto;
  min-width: 20px;
  padding: 0 4px;
`;

export default function Win95Window({ title, onClose, children, style }: Win95WindowProps) {
  return (
    <WindowWrapper style={style}>
      <Window style={{ width: "100%", flex: 1 }}>
        <StyledWindowHeader active>
          <TitleText>{title}</TitleText>
          {onClose && (
            <CloseButton size="sm" onClick={onClose}>
              <span style={{ fontWeight: "bold" }}>X</span>
            </CloseButton>
          )}
        </StyledWindowHeader>
        <WindowContent>{children}</WindowContent>
      </Window>
    </WindowWrapper>
  );
}
