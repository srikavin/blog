import React from 'react';
import {
    Alignment,
    Button,
    Menu,
    MenuItem,
    Navbar,
    NavbarDivider,
    NavbarGroup,
    NavbarHeading,
    Popover,
    Position
} from '@blueprintjs/core';
import NavLink from './NavLink/NavLink';
import AuthController from '../../util/AuthController';

class Navigation extends React.Component {
    render() {
        return (
            <nav>
                <Navbar>
                    <NavbarGroup align={Alignment.LEFT}>
                        <NavbarHeading>
                            Blog
                        </NavbarHeading>
                        <NavbarDivider/>
                        <NavLink to="/" icon="home" label="Home"/>
                    </NavbarGroup>
                    <NavbarGroup align={Alignment.RIGHT}>
                        {AuthController.getInstance().isLoggedIn() ? (
                            <Popover content={<Menu>
                                <MenuItem text="Profile" icon="user"/>
                                <MenuItem text="Logout" icon="log-out"/>
                            </Menu>} position={Position.BOTTOM}>
                                <Button icon="user" text="Username should be here"/>
                            </Popover>
                        ) : (
                            <NavLink to="/login" icon="log-in" label="Login"/>
                        )}
                    </NavbarGroup>
                </Navbar>
            </nav>
        )
    }
}

export default Navigation;