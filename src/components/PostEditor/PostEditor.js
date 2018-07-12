import React from 'react';

import {css, StyleSheet} from 'aphrodite';
import {store} from '../../data/store';
import MarkdownEditor from './MarkdownEditor/MarkdownEditor';
import {EditableText, NonIdealState, Spinner} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons'

class PostEditor extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            loading: true
        }
    }

    componentDidMount() {
        store.find('post', this.props.match.params.id)
            .then((e) => {
                this.setState({
                    post: e,
                    loading: false
                })
            })
            .catch((err) => {
                console.error(err);
                this.setState({
                    error: true,
                    loading: false
                })
            });
    }

    update() {
        store.update('post', this.props.match.params.id, {
            ...this.state.post
        }).then(e => {
            this.setState({
                post: e
            })
        }).catch(() => {
            this.setState({
                error: true
            })
        });
    }

    render() {
        if (this.state.error) {
            return <NonIdealState className={css(styles.errorBody)} title={'Unable to edit this post'}
                                  description={'An error occurred while loading the post editor'}
                                  icon={IconNames.ERROR}
            />
        }

        if (this.state.loading || !this.state.post) {
            return <Spinner className={css(styles.loader)}/>
        }

        return (
            <div className={css(styles.editorContainer)}>
                <EditableText className={css(styles.title)} value={this.state.post.title} selectAllOnFocus={true}/>
                <MarkdownEditor value={this.state.post.contents}/>
            </div>
        )
    }
}

const styles = StyleSheet.create({
    editorContainer: {},
    errorBody: {
        marginTop: '20px'
    },
    title: {
        marginTop: '5px',
        left: '50%',
        transform: 'translateX(-50%)',
        fontFamily: 'Dosis, sans-serif',
        fontSize: '76px',
        fontWeight: 'lighter',
        lineHeight: '80px'
    },
    loader: {
        marginTop: '20px',
        width: '20vw',
        height: '20vh',
        marginLeft: '40vw',
        marginRight: '40vw'
    }
});

export default PostEditor;
